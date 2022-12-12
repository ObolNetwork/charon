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

package bootnode

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"time"

	"github.com/libp2p/go-libp2p/core/metrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/promauto"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

// Config defines the config of the bootnode.
type Config struct {
	DataDir        string
	HTTPAddr       string
	MonitoringAddr string
	P2PConfig      p2p.Config
	LogConfig      log.Config
	AutoP2PKey     bool
	MaxResPerPeer  int
	MaxConns       int
	RelayLogLevel  string
}

// Run starts an Obol libp2p-tcp-relay and udp-discv5 bootnode.
func Run(ctx context.Context, config Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ctx = log.WithTopic(ctx, "bootnode")

	version.LogInfo(ctx, "Charon bootnode starting")

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

	// Setup p2p udp discovery.
	localEnode, db, err := p2p.NewLocalEnode(config.P2PConfig, key)
	if err != nil {
		return errors.Wrap(err, "failed to open enode")
	}
	defer db.Close()

	udpNode, err := p2p.NewUDPNode(ctx, config.P2PConfig, localEnode, key, nil)
	if err != nil {
		return err
	}
	defer udpNode.Close()

	reporter := metrics.NewBandwidthCounter()

	tcpNode, err := startP2P(ctx, config, key, reporter)
	if err != nil {
		return err
	}

	go monitorConnections(ctx, tcpNode, reporter)

	labels := map[string]string{
		"bootnode_peer": p2p.PeerName(tcpNode.ID()),
	}
	log.SetLokiLabels(labels)
	promRegistry, err := promauto.NewRegistry(labels)
	if err != nil {
		return err
	}

	// Start serving HTTP: ENR and monitoring.
	serverErr := make(chan error, 2)
	go func() {
		if config.HTTPAddr == "" {
			return
		}

		mux := http.NewServeMux()
		mux.HandleFunc("/enr", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(localEnode.Node().String()))
		})
		server := http.Server{Addr: config.HTTPAddr, Handler: mux, ReadHeaderTimeout: time.Second}
		serverErr <- server.ListenAndServe()
	}()

	go func() {
		if config.MonitoringAddr == "" {
			return
		}

		// Serve prometheus metrics wrapped with bootnode identifiers.
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.InstrumentMetricHandler(
			promRegistry, promhttp.HandlerFor(promRegistry, promhttp.HandlerOpts{}),
		))

		// Copied from net/http/pprof/pprof.go
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

		server := http.Server{Addr: config.MonitoringAddr, Handler: mux, ReadHeaderTimeout: time.Second}
		serverErr <- server.ListenAndServe()
	}()

	log.Info(ctx, "Libp2p TCP relay started",
		z.Str("peer_name", p2p.PeerName(tcpNode.ID())),
		z.Any("p2p_tcp_addr", config.P2PConfig.TCPAddrs),
	)
	log.Info(ctx, "Discv5 UDP bootnode started",
		z.Str("p2p_udp_addr", config.P2PConfig.UDPAddr),
		z.Str("enr", localEnode.Node().String()),
	)
	if config.HTTPAddr != "" {
		log.Info(ctx, "Runtime ENR available via http",
			z.Str("url", fmt.Sprintf("http://%s/enr", config.HTTPAddr)),
		)
	} else {
		log.Info(ctx, "Runtime ENR not available via http, since bootnode-http-address flag is not set")
	}

	ticker := time.NewTicker(time.Minute)
	for {
		select {
		case err := <-serverErr:
			return err
		case <-ticker.C:
			log.Info(ctx, "Discv5 UDP discovered peers", z.Int("peers", len(udpNode.AllNodes())))
		case <-ctx.Done():
			log.Info(ctx, "Shutting down")
			return nil
		}
	}
}
