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
	"net"
	"os"
	"path"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/types"
)

type simnetConfig struct {
	clusterDir string
	numNodes   int
	threshold  int
	tcpAddress string
	udpAddress string
}

func newGenSimnetCmd(runFunc func(simnetConfig) error) *cobra.Command {
	var conf simnetConfig

	cmd := &cobra.Command{
		Use:  "gen-simnet",
		Long: "Generate local simnet cluster",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(conf)
		},
	}

	bindSimnetFlags(cmd.Flags(), &conf)

	return cmd
}

func bindSimnetFlags(flags *pflag.FlagSet, config *simnetConfig) {
	flags.StringVar(&config.clusterDir, "cluster-dir", "./clusterData", "The root folder to create the cluster files and scripts")
	flags.IntVarP(&config.numNodes, "nodes", "n", 5, "The number of charon nodes in the cluster")
	flags.IntVarP(&config.threshold, "threshold", "t", 3, "The threshold required for signatures")
	flags.StringVar(&config.tcpAddress, "tcp-address", "127.0.0.1:8080", "TCP address for lib-p2p tcp")
	flags.StringVar(&config.udpAddress, "udp-address", "127.0.0.1:3030", "UDP address for discv5 udp")
}

func runGenSimnet(config simnetConfig) error {
	if err := os.Mkdir(config.clusterDir, 0o755); err != nil {
		return errors.Wrap(err, "mkdir")
	}

	var peers []types.Peer
	for i := 0; i < config.numNodes; i++ {
		dirname := fmt.Sprintf(config.clusterDir+"/node%d", i)
		if err := os.Mkdir(dirname, 0o755); err != nil {
			return errors.Wrap(err, "mkdir")
		}

		p2pKey, err := app.LoadOrCreatePrivKey(dirname)
		if err != nil {
			return errors.Wrap(err, "create p2p key")
		}

		tcp, err := net.ResolveTCPAddr("tcp", config.tcpAddress)
		if err != nil {
			return errors.Wrap(err, "resolve tcp address")
		}

		udp, err := net.ResolveUDPAddr("udp", config.udpAddress)
		if err != nil {
			return errors.Wrap(err, "resolve udp address")
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

	return nil
}
