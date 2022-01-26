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

// Package runner provides the top app-level abstraction and entrypoint for a charon DVC instance.
package runner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"
	"path"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	zerologger "github.com/rs/zerolog/log"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/discovery"
	"github.com/obolnetwork/charon/identity"
	"github.com/obolnetwork/charon/internal"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/runner/tracer"
	"github.com/obolnetwork/charon/validatorapi"
)

// log is a convenience handle to the global logger.
var log = zerologger.Logger

const (
	nodekeyFile = "nodekey"
)

type Config struct {
	Discovery        discovery.Config
	ClusterDir       string
	DataDir          string
	MonitoringAddr   string
	MonitoringPort   int
	ValidatorAPIAddr string
	ValidatorAPIPort int
	BeaconNodeAddr   string
	JaegerAddr       string
}

// Run is the entrypoint for running a charon DVC instance.
// All processes and their dependencies are constructed and then started.
// Graceful shutdown is triggered on first process error or when the shutdown context is cancelled.
func Run(shutdownCtx context.Context, conf Config) error {
	nodekey := path.Join(conf.DataDir, nodekeyFile)

	log.Info().Str("version", internal.ReleaseVersion).Msg("Charon starting")
	setStartupMetrics()

	// Construct processes and their dependencies
	// TODO(corver): Split this into high level methods like; setupApp, setupP2P, setupMonitoring, setupValidatorAPI, etc.

	stopJeager, err := tracer.Init(tracer.WithJaegerOrNoop(conf.JaegerAddr))
	if err != nil {
		return fmt.Errorf("init jaeger tracing: %w", err)
	}

	p2pKey, err := identity.P2PStore{KeyPath: nodekey}.Get()
	if err != nil {
		return fmt.Errorf("load or create peer ID: %w", err)
	}

	peerDB, err := discovery.NewPeerDB(&conf.Discovery, conf.Discovery.P2P, p2pKey)
	if err != nil {
		return fmt.Errorf("new peer db: %w", err)
	}

	discoveryNode := discovery.NewNode(&conf.Discovery, peerDB, p2pKey)

	manifests, err := cluster.LoadKnownClustersFromDir(conf.ClusterDir)
	if err != nil {
		return fmt.Errorf("load known cluster: %w", err)
	}
	log.Info().Msgf("Loaded %d DVs", len(manifests.Clusters()))

	connGater := p2p.NewConnGaterForClusters(manifests, nil)
	log.Info().Msgf("Connecting to %d unique peers", len(connGater.PeerIDs))

	_, err = p2p.NewNode(conf.Discovery.P2P, p2pKey, connGater)
	if err != nil {
		return fmt.Errorf("new p2p node: %w", err)
	}

	monitoring := newMonitoring(conf.MonitoringAddr)

	vhandler := validatorapi.Handler(nil) // TODO(corver): Construct this
	vrouter, err := validatorapi.NewRouter(vhandler, conf.BeaconNodeAddr)
	if err != nil {
		return fmt.Errorf("new monitoring server: %w", err)
	}
	vserver := http.Server{
		Addr:    conf.ValidatorAPIAddr,
		Handler: vrouter,
	}

	// Start processes and wait for first error or shutdown.

	var procErr error
	select {
	case err := <-start(monitoring.ListenAndServe):
		procErr = fmt.Errorf("monitoring server: %w", err)
	case err := <-start(discoveryNode.Listen):
		procErr = fmt.Errorf("discv5 server: %w", err)
	case err := <-start(vserver.ListenAndServe):
		procErr = fmt.Errorf("validatorapi server: %w", err)
	case <-shutdownCtx.Done():
		log.Info().Msgf("Shutdown signal detected")
	}
	if procErr != nil {
		// Even though procErr is returned below, also log it in case shutdown errors.
		log.Error().Err(err).Msg("Process error")
	}

	log.Info().Msgf("Shutting down gracefully")

	// Shutdown processes (allow 10s)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	discoveryNode.Close()

	if err := monitoring.Shutdown(ctx); err != nil {
		return fmt.Errorf("stop monitoring server: %w", err)
	}

	if err := vserver.Shutdown(ctx); err != nil {
		return fmt.Errorf("stop validatorapi server: %w", err)
	}

	if err := stopJeager(ctx); err != nil {
		return fmt.Errorf("stop jaeger tracer: %w", err)
	}

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
