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
	"net/http"
	"net/http/pprof"
	"path"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/tracer"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/discovery"
	"github.com/obolnetwork/charon/identity"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/validatorapi"
)

const (
	nodekeyFile = "nodekey"
)

type Config struct {
	Discovery        discovery.Config
	P2P              p2p.Config
	ClusterDir       string
	DataDir          string
	MonitoringAddr   string
	ValidatorAPIAddr string
	BeaconNodeAddr   string
	JaegerAddr       string
}

// Run is the entrypoint for running a charon DVC instance.
// All processes and their dependencies are constructed and then started.
// Graceful shutdown is triggered on first process error or when the shutdown context is cancelled.
//nolint:contextcheck
func Run(ctx context.Context, conf Config) error {
	ctx = log.WithComponent(ctx, "app-start")
	nodekey := path.Join(conf.DataDir, nodekeyFile)

	log.Info(ctx).Str("version", version.Version).Msg("Charon starting")
	setStartupMetrics()

	// Construct processes and their dependencies
	// TODO(corver): Split this into high level methods like; setupApp, setupP2P, setupMonitoring, setupValidatorAPI, etc.

	stopJeager, err := tracer.Init(tracer.WithJaegerOrNoop(conf.JaegerAddr))
	if err != nil {
		return errors.Wrap(err, "init jaeger tracing")
	}

	p2pKey, err := identity.P2PStore{KeyPath: nodekey}.Get()
	if err != nil {
		return errors.Wrap(err, "load or create peer ID")
	}

	localEnode, peerDB, err := discovery.NewLocalEnode(conf.Discovery, conf.P2P, p2pKey)
	if err != nil {
		return errors.Wrap(err, "create local enode")
	}

	discoveryNode, err := discovery.NewListener(conf.Discovery, conf.P2P, localEnode, p2pKey)
	if err != nil {
		return errors.Wrap(err, "start discv5 listener")
	}

	manifests, err := cluster.LoadKnownClustersFromDir(conf.ClusterDir)
	if err != nil {
		return errors.Wrap(err, "load known cluster")
	}

	log.Info(ctx).Int("n", len(manifests.Clusters())).Msg("Clusters loaded")

	connGater := p2p.NewConnGaterForClusters(manifests, nil)
	log.Info(ctx).Msgf("Connecting to %d unique peers", len(connGater.PeerIDs))

	_, err = p2p.NewNode(conf.P2P, p2pKey, connGater)
	if err != nil {
		return errors.Wrap(err, "new p2p node")
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

	var procErr error
	select {
	case err := <-start(monitoring.ListenAndServe):
		procErr = errors.Wrap(err, "monitoring server")
	case err := <-start(vserver.ListenAndServe):
		procErr = errors.Wrap(err, "validatorapi server")
	case <-ctx.Done():
		log.Info(ctx).Msg("Shutdown signal detected")
	}

	if procErr != nil {
		// Even though procErr is returned below, also log it in case shutdown errors.
		log.Error(ctx, procErr).Msg("Process error")
	}

	log.Info(ctx).Msg("Shutting down gracefully")

	// Shutdown processes with a fresh context allowing 10s.

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	ctx = log.WithComponent(ctx, "app-stop")

	discoveryNode.Close()

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
