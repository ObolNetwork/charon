// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	relaylog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

// BootnodeConfig defines the config of the bootnode.
type BootnodeConfig struct {
	DataDir       string
	HTTPAddr      string
	P2PConfig     p2p.Config
	LogConfig     log.Config
	AutoP2PKey    bool
	P2PRelay      bool
	MaxResPerPeer int
	MaxConns      int
	RelayLogLevel string
}

func newBootnodeCmd(runFunc func(context.Context, BootnodeConfig) error) *cobra.Command {
	var config BootnodeConfig

	cmd := &cobra.Command{
		Use:   "bootnode",
		Short: "Start a discv5 bootnode server",
		Long:  `Starts a discv5 bootnode that charon nodes can use to bootstrap their p2p cluster`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.Context(), config)
		},
	}

	bindDataDirFlag(cmd, &config.DataDir)
	bindBootnodeFlag(cmd.Flags(), &config)
	bindP2PFlags(cmd.Flags(), &config.P2PConfig)
	bindLogFlags(cmd.Flags(), &config.LogConfig)

	return cmd
}

func bindBootnodeFlag(flags *pflag.FlagSet, config *BootnodeConfig) {
	flags.StringVar(&config.HTTPAddr, "bootnode-http-address", "127.0.0.1:3640", "Listening address (ip and port) for the bootnode http server serving runtime ENR")
	flags.BoolVar(&config.AutoP2PKey, "auto-p2pkey", true, "Automatically create a p2pkey (ecdsa private key used for p2p authentication and ENR) if none found in data directory")
	flags.BoolVar(&config.P2PRelay, "p2p-relay", true, "Enable libp2p tcp host providing circuit relay to charon clusters")
	flags.StringVar(&config.RelayLogLevel, "p2p-relay-loglevel", "", "Libp2p circuit relay log level. E.g., debug, info, warn, error")

	// Decrease defaults after this has been addressed https://github.com/libp2p/go-libp2p/issues/1713
	flags.IntVar(&config.MaxResPerPeer, "max-reservations", 512, "Updates max circuit reservations per peer (each valid for 30min)") // TODO(corver): Align flag name to p2p-max-reservations
	flags.IntVar(&config.MaxConns, "p2p-max-connections", 16384, "Libp2p maximum number of peers that can connect to this bootnode.")
}

// RunBootnode starts a p2p-udp discv5 bootnode.
func RunBootnode(ctx context.Context, config BootnodeConfig) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ctx = log.WithTopic(ctx, "bootnode")

	if err := log.InitLogger(config.LogConfig); err != nil {
		return err
	}

	key, err := p2p.LoadPrivKey(config.DataDir)
	if errors.Is(err, os.ErrNotExist) {
		if !config.AutoP2PKey {
			return errors.New("charon-enr-private-key not found in data dir (run with --auto-p2pkey to auto generate)")
		}

		log.Info(ctx, "Automatically creating charon-enr-private-key", z.Str("path", p2p.KeyPath(config.DataDir)))

		key, err = p2p.NewSavedPrivKey(config.DataDir)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	// Setup p2p udp discovery
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

	// Setup p2p tcp relay (async for snappy startup)
	var (
		p2pErr = make(chan error, 1)
		logP2P = func() {}
	)

	go func() {
		if !config.P2PRelay {
			return
		}

		if config.RelayLogLevel != "" {
			if err := relaylog.SetLogLevel("relay", config.RelayLogLevel); err != nil {
				p2pErr <- errors.Wrap(err, "set relay log level")
				return
			}
		}

		// Increase resource limits
		limiter := rcmgr.DefaultLimits
		limiter.SystemBaseLimit.ConnsInbound = config.MaxConns
		limiter.SystemBaseLimit.FD = config.MaxConns
		limiter.TransientBaseLimit = limiter.SystemBaseLimit

		mgr, err := rcmgr.NewResourceManager(rcmgr.NewFixedLimiter(limiter.Scale(1<<30, config.MaxConns))) // 1GB Memory
		if err != nil {
			p2pErr <- errors.Wrap(err, "new resource manager")
		}

		tcpNode, err := p2p.NewTCPNode(config.P2PConfig, key, p2p.NewOpenGater(), libp2p.ResourceManager(mgr))
		if err != nil {
			p2pErr <- errors.Wrap(err, "new tcp node")
			return
		}

		// Reservations are valid for 30min (github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay/constraints.go:14)
		relayResources := relay.DefaultResources()
		relayResources.MaxReservationsPerPeer = config.MaxResPerPeer
		relayResources.MaxReservationsPerIP = config.MaxResPerPeer
		relayResources.MaxReservations = config.MaxConns

		relayService, err := relay.New(tcpNode, relay.WithResources(relayResources))
		if err != nil {
			p2pErr <- err
			return
		}

		logP2P = func() {
			peers := make(map[peer.ID]bool)
			conns := tcpNode.Network().Conns()
			for _, conn := range conns {
				peers[conn.RemotePeer()] = true
			}
			log.Info(ctx, "Libp2p TCP open connections",
				z.Int("total", len(conns)),
				z.Int("peers", len(peers)),
			)
		}

		log.Info(ctx, "Libp2p TCP relay started",
			z.Str("peer_name", p2p.PeerName(tcpNode.ID())),
			z.Any("p2p_tcp_addr", config.P2PConfig.TCPAddrs),
		)

		<-ctx.Done()
		_ = tcpNode.Close()
		_ = relayService.Close()
	}()

	// Start serving http
	serverErr := make(chan error, 1)
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/enr", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(localEnode.Node().String()))
		})
		server := http.Server{Addr: config.HTTPAddr, Handler: mux, ReadHeaderTimeout: time.Second}
		serverErr <- server.ListenAndServe()
	}()

	log.Info(ctx, "Discv5 UDP bootnode started",
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
		case err := <-p2pErr:
			return err
		case <-ticker.C:
			log.Info(ctx, "Discv5 UDP discovered peers", z.Int("peers", len(udpNode.AllNodes())))
			logP2P()
		case <-ctx.Done():
			log.Info(ctx, "Shutting down")
			return nil
		}
	}
}
