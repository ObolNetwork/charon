// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"text/template"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil/keystore"
)

const scriptTmpl = `#!/usr/bin/env bash

# This script run a charon node using the p2pkey in the
# local directory and the manifest in the parent directory

{{.CharonBin}} run \
{{range .Flags}}  {{.}} \
{{end}}`

const clusterTmpl = `#!/usr/bin/env bash

# This script runs all the charon nodes in
# the sub-directories; the whole cluster.

if (type -P tmux >/dev/null && type -P teamocil >/dev/null); then
  echo "Commands tmux and teamocil are installed"
  tmux new-session 'teamocil --layout teamocil.yml'
else
  echo "Commands tmux and teamocil are not installed, output will be merged"

  trap "exit" INT TERM ERR
  trap "kill 0" EXIT

  {{range .}} {{.}} &
  {{end}}

  wait
fi
`

const teamocilTmpl = `
windows:
  - name: charon-simnet
    root: /tmp/charon-simnet
    layout: tiled
    panes: {{range .}}
      -  {{.}}
{{end}}
`

type simnetConfig struct {
	ClusterDir string
	NumNodes   int
	Threshold  int
	PortStart  int
	Clean      bool

	// TestBinary overrides the charon binary for testing.
	TestBinary string
}

func newGenSimnetCmd(runFunc func(io.Writer, simnetConfig) error) *cobra.Command {
	var conf simnetConfig

	cmd := &cobra.Command{
		Use:   "gen-simnet",
		Short: "Generates local charon simnet cluster",
		Long: "Generate local charon simnet cluster. A simnet is a " +
			"simulated network that doesn't use actual beacon " +
			"nodes or validator clients but mocks them instead. " +
			"It showcases a running charon in isolation.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.OutOrStdout(), conf)
		},
	}

	bindSimnetFlags(cmd.Flags(), &conf)

	return cmd
}

func bindSimnetFlags(flags *pflag.FlagSet, config *simnetConfig) {
	flags.StringVar(&config.ClusterDir, "cluster-dir", "/tmp/charon-simnet", "The root folder to create the cluster files and scripts")
	flags.IntVarP(&config.NumNodes, "nodes", "n", 4, "The number of charon nodes in the cluster")
	flags.IntVarP(&config.Threshold, "Threshold", "t", 3, "The Threshold required for signatures")
	flags.IntVar(&config.PortStart, "port-start", 15000, "Starting port number for nodes in cluster")
	flags.BoolVar(&config.Clean, "clean", false, "Delete the cluster directory before generating it")
}

func runGenSimnet(out io.Writer, config simnetConfig) error {
	if config.Clean {
		// Remove previous directories
		if err := os.RemoveAll(config.ClusterDir); err != nil {
			return errors.Wrap(err, "remove cluster dir")
		}
	}

	// Create cluster directory at given location
	if err := os.MkdirAll(config.ClusterDir, 0o755); err != nil {
		return errors.Wrap(err, "mkdir")
	}

	charonBin := config.TestBinary
	if charonBin == "" {
		var err error
		charonBin, err = os.Executable()
		if err != nil {
			return errors.Wrap(err, "get charon binary")
		}
	}

	nodeDir := nodeDirFunc(config.ClusterDir)
	nextPort := nextPortFunc(config.PortStart)

	var peers []p2p.Peer
	for i := 0; i < config.NumNodes; i++ {
		peer, err := newPeer(config.ClusterDir, nodeDir(i), charonBin, i, nextPort)
		if err != nil {
			return errors.Wrap(err, "new peer", z.Int("i", i))
		}

		peers = append(peers, peer)
	}

	tss, shares, err := tbls.GenerateTSS(config.Threshold, config.NumNodes, rand.Reader)
	if err != nil {
		return errors.Wrap(err, "generate tss")
	}

	if err := writeManifest(config, tss, peers); err != nil {
		return err
	}

	// Write shares
	for i, share := range shares {
		secret, err := tblsconv.ShareToSecret(share)
		if err != nil {
			return err
		}

		err = keystore.StoreKeys([]*bls_sig.SecretKey{secret}, nodeDir(i))
		if err != nil {
			return err
		}
	}

	err = writeClusterScript(config.ClusterDir, config.NumNodes)
	if err != nil {
		return errors.Wrap(err, "write cluster script")
	}

	err = writeTeamocilYML(config.ClusterDir, config.NumNodes)
	if err != nil {
		return errors.Wrap(err, "write teamocil.yml")
	}

	writeOutput(out, config, charonBin, "simnet cluster")

	return nil
}

func writeManifest(config simnetConfig, tss tbls.TSS, peers []p2p.Peer) error {
	manifest := app.Manifest{
		DVs:   []tbls.TSS{tss},
		Peers: peers,
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", " ")
	if err != nil {
		return errors.Wrap(err, "json marshal manifest")
	}

	manifestPath := path.Join(config.ClusterDir, "manifest.json")
	if err = os.WriteFile(manifestPath, manifestJSON, 0o600); err != nil {
		return errors.Wrap(err, "write manifest.json")
	}

	return nil
}

// newPeer returns a new peer, generating a p2pkey and ENR and node directory and run script in the process.
func newPeer(clusterDir, nodeDir, charonBin string, peerIdx int, nextPort func() int) (p2p.Peer, error) {
	tcp := net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: nextPort(),
	}

	udp := net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: nextPort(),
	}

	p2pKey, err := p2p.NewSavedPrivKey(nodeDir)
	if err != nil {
		return p2p.Peer{}, errors.Wrap(err, "create p2p key")
	}

	var r enr.Record
	r.Set(enr.IPv4(tcp.IP))
	r.Set(enr.TCP(tcp.Port))
	r.Set(enr.UDP(udp.Port))
	r.SetSeq(0)

	err = enode.SignV4(&r, p2pKey)
	if err != nil {
		return p2p.Peer{}, errors.Wrap(err, "enode sign")
	}

	peer, err := p2p.NewPeer(r, peerIdx)
	if err != nil {
		return p2p.Peer{}, errors.Wrap(err, "new peer")
	}

	if err := writeRunScript(clusterDir, nodeDir, charonBin, nextPort(),
		tcp.String(), udp.String(), nextPort()); err != nil {
		return p2p.Peer{}, errors.Wrap(err, "write run script")
	}

	return peer, nil
}

// writeOutput writes the gen_simnet output.
func writeOutput(out io.Writer, config simnetConfig, charonBin string, name string) {
	var sb strings.Builder
	_, _ = sb.WriteString(fmt.Sprintf("Referencing charon binary in scripts: %s\n", charonBin))
	_, _ = sb.WriteString(fmt.Sprintf("Created %s:\n\n", name))
	_, _ = sb.WriteString(strings.TrimSuffix(config.ClusterDir, "/") + "/\n")
	_, _ = sb.WriteString("├─ manifest.json\tCluster manifest defines the cluster; used by all nodes\n")
	_, _ = sb.WriteString("├─ run_cluster.sh\tConvenience script to run all nodes\n")
	_, _ = sb.WriteString("├─ teamocil.yml\t\tConfiguration for teamocil utility to show output in different tmux panes\n")
	_, _ = sb.WriteString("├─ node[0-3]/\t\tDirectory for each node\n")
	_, _ = sb.WriteString("│  ├─ p2pkey\t\tP2P networking private key for node authentication\n")
	_, _ = sb.WriteString("│  ├─ keystore-*.json\tValidator private share key for duty signing\n")
	_, _ = sb.WriteString("│  ├─ keystore-*.txt\tBuddy password file for keystore-0.json\n")
	_, _ = sb.WriteString("│  ├─ run.sh\t\tScript to run the node\n")

	_, _ = fmt.Fprint(out, sb.String())
}

// writeRunScript creates run script for a node.
func writeRunScript(clusterDir string, nodeDir string, charonBin string, monitoringPort int,
	tcpAddr string, udpAddr string, validatorAPIPort int,
) error {
	f, err := os.Create(nodeDir + "/run.sh")
	if err != nil {
		return errors.Wrap(err, "create run.sh")
	}
	defer f.Close()

	// Flags for running a node
	var flags []string
	flags = append(flags, fmt.Sprintf("--data-dir=\"%s\"", nodeDir))
	flags = append(flags, fmt.Sprintf("--manifest-file=\"%s/manifest.json\"", clusterDir))
	flags = append(flags, fmt.Sprintf("--monitoring-address=\"127.0.0.1:%d\"", monitoringPort))
	flags = append(flags, fmt.Sprintf("--validator-api-address=\"127.0.0.1:%d\"", validatorAPIPort))
	flags = append(flags, fmt.Sprintf("--p2p-tcp-address=%s", tcpAddr))
	flags = append(flags, fmt.Sprintf("--p2p-udp-address=%s", udpAddr))
	flags = append(flags, "--simnet-beacon-mock")
	flags = append(flags, "--simnet-validator-mock")

	tmpl, err := template.New("").Parse(scriptTmpl)
	if err != nil {
		return errors.Wrap(err, "new template")
	}

	err = tmpl.Execute(f, struct {
		CharonBin string
		Flags     []string
	}{CharonBin: charonBin, Flags: flags})
	if err != nil {
		return errors.Wrap(err, "execute template")
	}

	err = os.Chmod(nodeDir+"/run.sh", 0o755)
	if err != nil {
		return errors.Wrap(err, "change permissions")
	}

	return nil
}

// writeClusterScript creates script to run all the nodes in the cluster.
func writeClusterScript(clusterDir string, n int) error {
	var cmds []string
	for i := 0; i < n; i++ {
		cmds = append(cmds, fmt.Sprintf("%s/node%d/run.sh", clusterDir, i))
	}

	f, err := os.Create(clusterDir + "/run_cluster.sh")
	if err != nil {
		return errors.Wrap(err, "create run cluster")
	}

	tmpl, err := template.New("").Parse(clusterTmpl)
	if err != nil {
		return errors.Wrap(err, "new template")
	}

	err = tmpl.Execute(f, cmds)
	if err != nil {
		return errors.Wrap(err, "execute template")
	}

	err = os.Chmod(clusterDir+"/run_cluster.sh", 0o755)
	if err != nil {
		return errors.Wrap(err, "change permissions")
	}

	return nil
}

// writeTeamocilYML creates teamocil configurations file to show the nodes output in different tmux panes.
func writeTeamocilYML(clusterDir string, n int) error {
	var cmds []string
	for i := 0; i < n; i++ {
		cmds = append(cmds, fmt.Sprintf("%s/node%d/run.sh", clusterDir, i))
	}

	f, err := os.Create(clusterDir + "/teamocil.yml")
	if err != nil {
		return errors.Wrap(err, "create teamocil.yml")
	}

	tmpl, err := template.New("").Parse(teamocilTmpl)
	if err != nil {
		return errors.Wrap(err, "new template")
	}

	err = tmpl.Execute(f, cmds)
	if err != nil {
		return errors.Wrap(err, "execute template")
	}

	err = os.Chmod(clusterDir+"/teamocil.yml", 0o644)
	if err != nil {
		return errors.Wrap(err, "change permissions")
	}

	return nil
}

// nodeDirFunc returns a node dir function.
func nodeDirFunc(clusterDir string) func(i int) string {
	return func(i int) string {
		return fmt.Sprintf("%s/node%d", clusterDir, i)
	}
}

// nextPortFunc returns a next port function starting at start port.
func nextPortFunc(startPort int) func() int {
	port := startPort
	return func() int {
		port++
		return port
	}
}
