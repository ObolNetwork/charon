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
	"text/template"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/types"
)

const scriptTmpl = `#!/bin/sh
{{.CharonDir}} run {{range .Flags}} {{.}} \
{{end}}`

const clusterTmpl = `#!/bin/sh
trap "exit" INT TERM ERR
trap "kill 0" EXIT

{{range .}} {{.}}
{{end}}

wait`

type simnetConfig struct {
	clusterDir string
	numNodes   int
	threshold  int
	portStart  int
}

func newGenSimnetCmd(runFunc func(io.Writer, simnetConfig) error) *cobra.Command {
	var conf simnetConfig

	cmd := &cobra.Command{
		Use:   "gen-simnet",
		Short: "Generates charon simnet cluster",
		Long:  "Generate local simnet cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.OutOrStdout(), conf)
		},
	}

	bindSimnetFlags(cmd.Flags(), &conf)

	return cmd
}

func bindSimnetFlags(flags *pflag.FlagSet, config *simnetConfig) {
	flags.StringVar(&config.clusterDir, "cluster-dir", "/tmp/charon-simnet", "The root folder to create the cluster files and scripts")
	flags.IntVarP(&config.numNodes, "nodes", "n", 4, "The number of charon nodes in the cluster")
	flags.IntVarP(&config.threshold, "threshold", "t", 3, "The threshold required for signatures")
	flags.IntVar(&config.portStart, "port-start", 15000, "Starting port number for nodes in cluster")
}

func runGenSimnet(out io.Writer, config simnetConfig) error {
	// Remove previous directories
	if err := os.RemoveAll(config.clusterDir); err != nil {
		return errors.Wrap(err, "remove cluster dir")
	}

	// Create cluster directory at given location
	if err := os.Mkdir(config.clusterDir, 0o755); err != nil {
		return errors.Wrap(err, "mkdir")
	}

	var peers []types.Peer
	port := config.portStart
	getPort := func() int {
		port++
		return port
	}
	for i := 0; i < config.numNodes; i++ {
		dirname := fmt.Sprintf(config.clusterDir+"/node%d", i)
		if err := os.Mkdir(dirname, 0o755); err != nil {
			return errors.Wrap(err, "mkdir")
		}

		p2pKey, err := app.LoadOrCreatePrivKey(dirname)
		if err != nil {
			return errors.Wrap(err, "create p2p key")
		}

		tcp := net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: getPort(),
		}

		udp := net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: getPort(),
		}

		var r enr.Record
		r.Set(enr.IPv4(tcp.IP))
		r.Set(enr.TCP(tcp.Port))
		r.Set(enr.UDP(udp.Port))
		r.SetSeq(0)

		err = enode.SignV4(&r, p2pKey)
		if err != nil {
			return errors.Wrap(err, "enode sign")
		}

		peer, err := types.NewPeer(r, i)
		if err != nil {
			return errors.Wrap(err, "new peer")
		}

		peers = append(peers, peer)

		// Write run command to a bash script for each node
		if err := writeRunScript(config.clusterDir, dirname, getPort(), tcp.String(), udp.String(), getPort()); err != nil {
			return errors.Wrap(err, "write run script")
		}
	}

	tss, _, err := tbls.GenerateTSS(config.threshold, config.numNodes, rand.Reader)
	if err != nil {
		return errors.Wrap(err, "generate tss")
	}

	manifest := types.Manifest{
		DVs:   []tbls.TSS{tss},
		Peers: peers,
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", " ")
	if err != nil {
		return errors.Wrap(err, "json marshal manifest")
	}

	filename := path.Join(config.clusterDir, "manifest.json")
	if err = os.WriteFile(filename, manifestJSON, 0o600); err != nil {
		return errors.Wrap(err, "write manifest.json")
	}

	err = writeClusterScript(config.clusterDir, config.numNodes)
	if err != nil {
		return errors.Wrap(err, "write cluster script")
	}

	_, _ = fmt.Fprintf(out, "Created a simnet cluster at: %s", config.clusterDir)

	return nil
}

// writeRunScript creates run script for each node.
func writeRunScript(clusterDir string, dirname string, monitoringPort int, tcpAddr string, udpAddr string, validatorAPIPort int) error {
	charonExe, err := os.Executable()
	if err != nil {
		return errors.Wrap(err, "getting current directory")
	}

	f, err := os.Create(dirname + "/run.sh")
	if err != nil {
		return errors.Wrap(err, "create run.sh")
	}
	defer f.Close()

	// Flags for running a node
	var flags []string
	flags = append(flags, fmt.Sprintf("--data-dir=\"%s\"", dirname))
	flags = append(flags, fmt.Sprintf("--manifest-file=\"%s/manifest.json\"", clusterDir))
	flags = append(flags, fmt.Sprintf("--monitoring-address=\"127.0.0.1:%d\"", monitoringPort))
	flags = append(flags, fmt.Sprintf("--validator-api-address=\"127.0.0.1:%d\"", validatorAPIPort))
	flags = append(flags, fmt.Sprintf("--p2p-tcp-address=%s", tcpAddr))
	flags = append(flags, fmt.Sprintf("--p2p-udp-address=%s", udpAddr))

	tmpl, err := template.New("run").Parse(scriptTmpl)
	if err != nil {
		return errors.Wrap(err, "new template")
	}

	err = tmpl.Execute(f, struct {
		CharonDir string
		Flags     []string
	}{CharonDir: charonExe, Flags: flags})
	if err != nil {
		return errors.Wrap(err, "execute template")
	}

	err = os.Chmod(dirname+"/run.sh", 0o755)
	if err != nil {
		return errors.Wrap(err, "change run.sh permissions")
	}

	return nil
}

// writeClusterScript creates script to run all the nodes in the cluster.
func writeClusterScript(dirname string, n int) error {
	var cmds []string
	for i := 0; i < n-1; i++ {
		cmds = append(cmds, fmt.Sprintf("node%d/run.sh &", i))
	}
	cmds = append(cmds, fmt.Sprintf("node%d/run.sh", n-1))
	f, err := os.Create(dirname + "/run-cluster.sh")
	if err != nil {
		return errors.Wrap(err, "create run cluster")
	}

	tmpl, err := template.New("run-cluster").Parse(clusterTmpl)
	if err != nil {
		return errors.Wrap(err, "new template")
	}

	err = tmpl.Execute(f, cmds)
	if err != nil {
		return errors.Wrap(err, "execute template")
	}

	err = os.Chmod(dirname+"/run-cluster.sh", 0o755)
	if err != nil {
		return errors.Wrap(err, "change run.sh permissions")
	}

	return nil
}
