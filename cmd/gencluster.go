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

type clusterConfig struct {
	ClusterDir string
	NumNodes   int
	Threshold  int
	PortStart  int
	Simnet     bool
	Clean      bool
	SplitKeys  bool
	KeysDir    string

	// TestBinary overrides the charon binary for testing.
	TestBinary string
}

func newGenClusterCmd(runFunc func(io.Writer, clusterConfig) error) *cobra.Command {
	var conf clusterConfig

	cmd := &cobra.Command{
		Use:   "gen-cluster",
		Short: "Generate local charon cluster",
		Long: "Generate local charon cluster including run scripts, cluster manifest " +
			"and node keys and config. See flags for supported features.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.OutOrStdout(), conf)
		},
	}

	bindClusterFlags(cmd.Flags(), &conf)

	return cmd
}

func bindClusterFlags(flags *pflag.FlagSet, config *clusterConfig) {
	flags.StringVar(&config.ClusterDir, "cluster-dir", "/tmp/charon", "The target folder to create the cluster in.")
	flags.IntVarP(&config.NumNodes, "nodes", "n", 4, "The number of charon nodes in the cluster.")
	flags.IntVarP(&config.Threshold, "threshold", "t", 3, "The threshold required for signatures.")
	flags.IntVar(&config.PortStart, "port-start", 16000, "Starting port number for nodes in cluster.")
	flags.BoolVar(&config.Simnet, "simnet", true, "Configures a simnet cluster with mock beacon node and mock validator clients. It showcases a running charon in isolation.")
	flags.BoolVar(&config.Clean, "clean", false, "Delete the cluster directory before generating it.")
	flags.BoolVar(&config.SplitKeys, "split-validator-keys", false, "Enables splitting of existing non-dvt validator keys into distributed threshold private shares (instead of creating new random keys).")
	flags.StringVar(&config.KeysDir, "keys-dir", "", "Directory containing keys to split. Expects keys in keystore-*.json and passwords in keystore-*.txt. Requires --split-validator-keys.")
}

func runGenCluster(w io.Writer, conf clusterConfig) error {
	if conf.Clean {
		// Remove previous directories
		if err := os.RemoveAll(conf.ClusterDir); err != nil {
			return errors.Wrap(err, "remove cluster dir")
		}
	}

	// Create cluster directory at given location
	if err := os.MkdirAll(conf.ClusterDir, 0o755); err != nil {
		return errors.Wrap(err, "mkdir")
	}

	// Get charon binary to include in run scripts
	charonBin, err := os.Executable()
	if err != nil {
		return errors.Wrap(err, "get charon binary")
	} else if conf.TestBinary != "" {
		charonBin = conf.TestBinary
	}

	// Get root bls key
	secrets, err := getKeys(conf)
	if err != nil {
		return err
	}

	// Get function to create sequential ports
	nextPort := nextPortFunc(conf.PortStart)

	// Generate threshold bls key shares
	var (
		dvs    []tbls.TSS
		splits [][]*bls_sig.SecretKeyShare
	)
	for _, secret := range secrets {
		shares, verifier, err := tbls.SplitSecret(secret, conf.Threshold, conf.NumNodes, rand.Reader)
		if err != nil {
			return err
		}

		splits = append(splits, shares)

		tss, err := tbls.NewTSS(verifier, len(shares))
		if err != nil {
			return err
		}

		dvs = append(dvs, tss)
	}

	// Create p2p peers
	var peers []p2p.Peer
	for i := 0; i < conf.NumNodes; i++ {
		peer, err := newPeer(conf.ClusterDir, nodeDir(conf.ClusterDir, i), charonBin, i, nextPort)
		if err != nil {
			return err
		}

		peers = append(peers, peer)

		var secrets []*bls_sig.SecretKey
		for _, split := range splits {
			secret, err := tblsconv.ShareToSecret(split[i])
			if err != nil {
				return err
			}
			secrets = append(secrets, secret)
		}

		if err := keystore.StoreKeys(secrets, nodeDir(conf.ClusterDir, i)); err != nil {
			return err
		}
	}

	// TODO(corver): Write deposit datas if not simnet

	if err := writeManifest(conf, dvs, peers); err != nil {
		return err
	}

	err = writeClusterScript(conf.ClusterDir, conf.NumNodes)
	if err != nil {
		return errors.Wrap(err, "write cluster script")
	}

	err = writeTeamocilYML(conf.ClusterDir, conf.NumNodes)
	if err != nil {
		return errors.Wrap(err, "write teamocil.yml")
	}

	writeOutput(w, conf, charonBin)

	return nil
}

func getKeys(conf clusterConfig) ([]*bls_sig.SecretKey, error) {
	if conf.SplitKeys {
		if conf.KeysDir == "" {
			return nil, errors.New("--keys-dir required when splitting keys")
		}

		return keystore.LoadKeys(conf.KeysDir)
	}

	// TODO(corver): Add flag to generate more distributed-validators than 1

	_, secret, err := tbls.KeygenWithSeed(rand.Reader)
	if err != nil {
		return nil, err
	}

	return []*bls_sig.SecretKey{secret}, nil
}

func writeManifest(config clusterConfig, tss []tbls.TSS, peers []p2p.Peer) error {
	manifest := app.Manifest{
		DVs:   tss,
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

// writeOutput writes the gen_cluster output.
func writeOutput(out io.Writer, config clusterConfig, charonBin string) {
	var sb strings.Builder
	_, _ = sb.WriteString(fmt.Sprintf("Referencing charon binary in scripts: %s\n", charonBin))
	_, _ = sb.WriteString("Created charon cluster:\n\n")
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

// nodeDir returns a node directory.
func nodeDir(clusterDir string, i int) string {
	return fmt.Sprintf("%s/node%d", clusterDir, i)
}

// nextPortFunc returns a next port function starting at start port.
func nextPortFunc(startPort int) func() int {
	port := startPort
	return func() int {
		port++
		return port
	}
}
