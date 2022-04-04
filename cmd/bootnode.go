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
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

type bootnodeConfig struct {
	DataDir    string
	HTTPAddr   string
	P2PConfig  p2p.Config
	LogConfig  log.Config
	AutoP2PKey bool
}

func newBootnodeCmd(runFunc func(context.Context, bootnodeConfig) error) *cobra.Command {
	var config bootnodeConfig

	cmd := &cobra.Command{
		Use:   "bootnode",
		Short: "Starts a p2p-udp discv5 bootnode",
		Long:  `Starts a p2p-udp discv5 bootnode that charon nodes can use to bootstrap their p2p cluster`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.Context(), config)
		},
	}

	bindDataDirFlag(cmd.Flags(), &config.DataDir)
	bindBootnodeFlag(cmd.Flags(), &config.HTTPAddr, &config.AutoP2PKey)
	bindP2PFlags(cmd.Flags(), &config.P2PConfig)
	bindLogFlags(cmd.Flags(), &config.LogConfig)

	return cmd
}

func bindBootnodeFlag(flags *pflag.FlagSet, httpAddr *string, autoP2PKey *bool) {
	flags.StringVar(httpAddr, "bootnode-http-address", "127.0.0.1:8088", "Listening address for the bootnode http server serving runtime ENR")
	flags.BoolVar(autoP2PKey, "auto-p2pkey", true, "Automatically create a p2pkey (ecdsa private key used for p2p authentication and ENR) if none found in data directory")
}

// runBootnode starts a p2p-udp discv5 bootnode.
func runBootnode(ctx context.Context, config bootnodeConfig) error {
	ctx = log.WithTopic(ctx, "bootnode")

	if err := log.InitLogger(config.LogConfig); err != nil {
		return err
	}

	key, err := p2p.LoadPrivKey(config.DataDir)
	if errors.Is(err, os.ErrNotExist) {
		if !config.AutoP2PKey {
			return errors.New("p2pkey not found in data dir (run with --auto-p2pkey to auto generate)")
		}

		log.Info(ctx, "Auto creating p2pkey", z.Str("path", p2p.KeyPath(config.DataDir)))

		key, err = p2p.NewSavedPrivKey(config.DataDir)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	localEnode, db, err := p2p.NewLocalEnode(config.P2PConfig, key)
	if err != nil {
		return errors.Wrap(err, "failed to open enode")
	}
	defer db.Close()

	udpNode, err := p2p.NewUDPNode(ctx, config.P2PConfig, localEnode, key, nil)
	if err != nil {
		return errors.Wrap(err, "")
	}
	defer udpNode.Close()

	serverErr := make(chan error, 1)
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/enr", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(localEnode.Node().String()))
		})
		server := http.Server{Addr: config.HTTPAddr, Handler: mux}
		serverErr <- server.ListenAndServe()
	}()

	log.Info(ctx, "Bootnode started",
		z.Str("http_addr", config.HTTPAddr),
		z.Str("p2p_udp_addr", config.P2PConfig.UDPAddr),
		z.Str("enr", localEnode.Node().String()),
	)
	log.Info(ctx, "Runtime ENR available via http",
		z.Str("url", fmt.Sprintf("http://%s/enr", config.HTTPAddr)),
	)

	ticker := time.NewTicker(time.Minute)
	for {
		select {
		case err := <-serverErr:
			return err
		case <-ticker.C:
			log.Info(ctx, "Connected node count", z.Int("n", len(udpNode.AllNodes())))
		case <-ctx.Done():
			log.Info(ctx, "Shutting down")
			return nil
		}
	}
}
