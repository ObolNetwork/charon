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

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/automaxprocs/maxprocs"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/tracer"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	leadercast "github.com/obolnetwork/charon/core/leadercast"
	"github.com/obolnetwork/charon/core/validatorapi"
	"github.com/obolnetwork/charon/p2p"
)

type Config struct {
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
	// Manifest provides the manifest explicitly, skips loading ManifestFile from disk.
	Manifest *Manifest
	// P2PKey provides the p2p privkey explicitly, skips loading from keystore on disk.
	P2PKey *ecdsa.PrivateKey
	// PingCallback is called when a ping was completed to a peer.
	PingCallback func(peer.ID)
	// SimDutyPeriod overrides the default duty simulator period of 5 seconds.
	SimDutyPeriod time.Duration
	// SimDutyCallback is called when the duty simulator resolves a mock duty.
	SimDutyCallback func(core.Duty, []byte)
}

// Run is the entrypoint for running a charon DVC instance.
// All processes and their dependencies are constructed and then started.
// Graceful shutdown is triggered on first process error or when the shutdown context is cancelled.
//nolint:contextcheck,revive,cyclop
func Run(ctx context.Context, conf Config) error {
	_, _ = maxprocs.Set()
	ctx = log.WithTopic(ctx, "app-start")

	testConf := conf.TestConfig

	log.Info(ctx, "Charon starting", z.Str("version", version.Version))
	setStartupMetrics()

	// Construct processes and their dependencies
	// TODO(corver): Split this into high level methods like; setupApp, setupP2P, setupMonitoring, setupValidatorAPI, etc.

	stopJeager, err := tracer.Init(tracer.WithJaegerOrNoop(conf.JaegerAddr))
	if err != nil {
		return errors.Wrap(err, "init jaeger tracing")
	}

	var manifest Manifest
	if conf.TestConfig.Manifest != nil {
		manifest = *conf.TestConfig.Manifest
	} else {
		manifest, err = loadManifest(conf.ManifestFile)
		if err != nil {
			return errors.Wrap(err, "load manifest")
		}
	}

	p2pKey := conf.TestConfig.P2PKey
	if p2pKey == nil {
		p2pKey, err = LoadOrCreatePrivKey(conf.DataDir)
		if err != nil {
			return errors.Wrap(err, "load or create peer ID")
		}
	}

	localEnode, peerDB, err := p2p.NewLocalEnode(conf.P2P, p2pKey)
	if err != nil {
		return errors.Wrap(err, "create local enode")
	}

	udpNode, err := p2p.NewUDPNode(conf.P2P, localEnode, p2pKey, manifest.ENRs())
	if err != nil {
		return errors.Wrap(err, "start discv5 listener")
	}

	connGater, err := p2p.NewConnGater(manifest.PeerIDs())
	if err != nil {
		return errors.Wrap(err, "connection gater")
	}

	tcpNode, err := p2p.NewTCPNode(conf.P2P, p2pKey, connGater, udpNode, manifest.Peers)
	if err != nil {
		return errors.Wrap(err, "new p2p node", z.Str("allowlist", conf.P2P.Allowlist))
	}

	index := -1
	for i, p := range manifest.PeerIDs() {
		if tcpNode.ID() == p {
			index = i
		}
	}
	if index == -1 {
		return errors.New("privkey not in manifest peers")
	}

	log.Info(ctx, "Manifest loaded",
		z.Int("peers", len(manifest.Peers)),
		z.Str("local_peer", p2p.ShortID(tcpNode.ID())),
		z.Int("index", index))

	monitoring := newMonitoring(conf.MonitoringAddr, localEnode)

	vhandler := validatorapi.Handler(nil) // TODO(corver): Construct this
	vrouter, err := validatorapi.NewRouter(vhandler, conf.BeaconNodeAddr)
	if err != nil {
		return errors.Wrap(err, "new monitoring server")
	}
	vserver := http.Server{
		Addr:    conf.ValidatorAPIAddr,
		Handler: vrouter,
	}

	lcast := leadercast.New(leadercast.NewP2PTransport(tcpNode, index, manifest.PeerIDs()), index, len(manifest.Peers))

	// Start processes and wait for first error or shutdown.

	go func() {
		_ = lcast.Run(ctx)
	}()

	stopPing := p2p.StartPingService(tcpNode, manifest.PeerIDs(), conf.TestConfig.PingCallback)

	startSim, stopSim := newDutySimulator(lcast, testConf.SimDutyPeriod, testConf.SimDutyCallback)

	var procErr error
	select {
	case err := <-start(monitoring.ListenAndServe):
		procErr = errors.Wrap(err, "monitoring server")
	case err := <-start(vserver.ListenAndServe):
		procErr = errors.Wrap(err, "validatorapi server")

	//	procErr = errors.Wrap(err, "leadercast consensus")
	case err := <-start(startSim):
		procErr = errors.Wrap(err, "duty simulator")
	case <-ctx.Done():
		log.Info(ctx, "Shutdown signal detected")
	}

	if procErr != nil {
		// Even though procErr is returned below, also log it in case shutdown errors.
		log.Error(ctx, "Process start error", procErr)
	}

	// Shutdown processes with a fresh context allowing 10s.

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	ctx = log.WithTopic(ctx, "app-stop")
	log.Info(ctx, "Shutting down gracefully")

	stopSim()
	stopPing()

	if err := tcpNode.Close(); err != nil {
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

	udpNode.Close()

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
func newMonitoring(addr string, localNode *enode.LocalNode) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	// Serve local ENR to allow simple HTTP Get to this node to resolve it as bootnode ENR.
	mux.Handle("/enr", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(localNode.Node().String()))
	}))

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
