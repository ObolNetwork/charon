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

// Package app provides the top app-level abstraction and entrypoint for a charon DVC instance.
// The sub-packages also provide app-level functionality.
package app

import (
	"context"
	"crypto/ecdsa"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/tracer"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/crypto"
	"github.com/obolnetwork/charon/discovery"
	"github.com/obolnetwork/charon/identity"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/validatorapi"
)

type Config struct {
	Discovery        discovery.Config
	P2P              p2p.Config
	ManifestFile     string
	DataDir          string
	MonitoringAddr   string
	ValidatorAPIAddr string
	BeaconNodeAddr   string
	JaegerAddr       string

	TestConfig TestConfig
}

// TestConfig defines additional test-only config.
type TestConfig struct {
	// Manifest provides the manifest explicitly, skipping loading ManifestFile from disk.
	Manifest cluster.Manifest
	// P2PKey provides the p2p privkey explicitly, skipping loading from keystore on disk.
	P2PKey *ecdsa.PrivateKey
	// ConnectAttempts defines synchronous peer connect at startup.
	ConnectAttempts int
	// PingCallback is called when a ping is received from a peer.
	PingCallback func(peer.ID)
}

// Run is the entrypoint for running a charon DVC instance.
// All processes and their dependencies are constructed and then started.
// Graceful shutdown is triggered on first process error or when the shutdown context is cancelled.
//nolint:contextcheck
func Run(ctx context.Context, conf Config) error {
	ctx = log.WithTopic(ctx, "app-start")

	log.Info(ctx, "Charon starting", z.Str("version", version.Version))
	setStartupMetrics()

	// Construct processes and their dependencies
	// TODO(corver): Split this into high level methods like; setupApp, setupP2P, setupMonitoring, setupValidatorAPI, etc.

	stopJeager, err := tracer.Init(tracer.WithJaegerOrNoop(conf.JaegerAddr))
	if err != nil {
		return errors.Wrap(err, "init jaeger tracing")
	}

	p2pKey := conf.TestConfig.P2PKey
	if p2pKey == nil {
		p2pKey, err = identity.LoadOrCreatePrivKey(conf.DataDir)
		if err != nil {
			return errors.Wrap(err, "load or create peer ID")
		}
	}

	localEnode, peerDB, err := discovery.NewLocalEnode(conf.Discovery, conf.P2P, p2pKey)
	if err != nil {
		return errors.Wrap(err, "create local enode")
	}

	discoveryNode, err := discovery.NewListener(conf.Discovery, conf.P2P, localEnode, p2pKey)
	if err != nil {
		return errors.Wrap(err, "start discv5 listener")
	}

	manifest := conf.TestConfig.Manifest
	if len(manifest.ENRs) == 0 {
		manifest, err = cluster.LoadManifest(conf.ManifestFile)
		if err != nil {
			return errors.Wrap(err, "load manifest")
		}
	}

	enrs, err := manifest.ParsedENRs()
	if err != nil {
		return err
	}

	peers, err := manifest.PeerIDs()
	if err != nil {
		return err
	}

	connGater, err := p2p.NewConnGater(peers)
	if err != nil {
		return errors.Wrap(err, "connection gater")
	}

	node, err := p2p.NewNode(conf.P2P, p2pKey, connGater)
	if err != nil {
		return errors.Wrap(err, "new p2p node", z.Str("allowlist", conf.P2P.Allowlist))
	}

	log.Info(ctx, "Manifest loaded",
		z.Int("peers", len(manifest.ENRs)),
		z.Str("local_peer", p2p.ShortID(node.ID())),
		z.Str("pubkey", crypto.BLSPointToHex(manifest.Pubkey())[:10]))

	if err := p2p.ConnectPeers(ctx, node, enrs, conf.TestConfig.ConnectAttempts); err != nil {
		return errors.Wrap(err, "connect peers")
	}

	monitoring := newMonitoring(conf.MonitoringAddr)

	vhandler := validatorapi.Handler(nil) // TODO(corver): Construct this
	vrouter, err := validatorapi.NewRouter(vhandler, conf.BeaconNodeAddr)
	if err != nil {
		return errors.Wrap(err, "new monitoring server")
	}
	vserver := http.Server{
		Addr:    conf.ValidatorAPIAddr,
		Handler: vrouter,
	}

	// Start processes and wait for first error or shutdown.

	stopPing := p2p.StartPingService(node, peers, conf.TestConfig.PingCallback)

	var procErr error
	select {
	case err := <-start(monitoring.ListenAndServe):
		procErr = errors.Wrap(err, "monitoring server")
	case err := <-start(vserver.ListenAndServe):
		procErr = errors.Wrap(err, "validatorapi server")
	case <-ctx.Done():
		log.Info(ctx, "Shutdown signal detected")
	}

	if procErr != nil {
		// Even though procErr is returned below, also log it in case shutdown errors.
		log.Error(ctx, "Process error", procErr)
	}

	// Shutdown processes with a fresh context allowing 10s.

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	ctx = log.WithTopic(ctx, "app-stop")
	log.Info(ctx, "Shutting down gracefully")

	stopPing()

	discoveryNode.Close()

	if err := node.Close(); err != nil {
		return errors.Wrap(err, "stop p2p node")
	}

	if err := monitoring.Shutdown(ctx); err != nil {
		return errors.Wrap(err, "stop monitoring server")
	}

	if err := vserver.Shutdown(ctx); err != nil {
		return errors.Wrap(err, "stop validatorapi server")
	}

	if err := stopJeager(ctx); err != nil {
		return errors.Wrap(err, "stop jaeger tracer")
	}

	peerDB.Close()

	return procErr
}

// start calls the function asynchronously and returns a channel that propagates
// a non-nil error response. Nil responses are dropped.
// Note this supports both blocking and non-blocking functions.
func start(fn func() error) <-chan error {
	ch := make(chan error, 1)

	go func() {
		err := fn()
		if err != nil {
			ch <- err
		}
	}()

	return ch
}

// newMonitoring returns the monitoring server providing prometheus metrics and pprof profiling.
func newMonitoring(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	// Copied from net/http/pprof/pprof.go
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	return &http.Server{
		Addr:    addr,
		Handler: mux,
	}
}
