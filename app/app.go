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
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/automaxprocs/maxprocs"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/lifecycle"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/tracer"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/leadercast"
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
// All processes and their dependencies are wired and added
// to the life cycle manager which handles starting and graceful shutdown.
func Run(ctx context.Context, conf Config) (err error) {
	ctx = log.WithTopic(ctx, "app-start")
	defer func() {
		if err != nil {
			log.Error(ctx, "Fatal run error", err)
		}
	}()

	log.Info(ctx, "Charon starting", z.Str("version", version.Version))

	_, _ = maxprocs.Set()
	initStartupMetrics()

	// Construct processes and their dependencies
	life := new(lifecycle.Manager)

	if err := initTracing(life, conf); err != nil {
		return err
	}

	manifest, err := loadManifest(conf)
	if err != nil {
		return err
	}

	tcpNode, localEnode, index, err := initP2P(ctx, life, conf, manifest)
	if err != nil {
		return err
	}

	log.Info(ctx, "Manifest loaded",
		z.Int("peers", len(manifest.Peers)),
		z.Str("local_peer", p2p.ShortID(tcpNode.ID())),
		z.Int("index", index))

	initMonitoring(life, conf.MonitoringAddr, localEnode)

	if err := initValdatorAPI(life, conf); err != nil {
		return err
	}

	initDutySimulator(life, tcpNode, index, manifest, conf)

	return life.Run(ctx)
}

func initDutySimulator(life *lifecycle.Manager, tcpNode host.Host, index int, manifest Manifest, conf Config) {
	lcast := leadercast.New(leadercast.NewP2PTransport(tcpNode, index, manifest.PeerIDs()), index, len(manifest.Peers))

	startSim := newDutySimulator(lcast, conf.TestConfig.SimDutyPeriod, conf.TestConfig.SimDutyCallback)

	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartLeaderCast, lifecycle.HookFunc(lcast.Run))
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartSimulator, lifecycle.HookFunc(startSim))
}

func initP2P(ctx context.Context, life *lifecycle.Manager, conf Config, manifest Manifest,
) (host.Host, *enode.LocalNode, int, error) {
	p2pKey := conf.TestConfig.P2PKey
	if p2pKey == nil {
		var err error
		var loaded bool
		p2pKey, loaded, err = LoadOrCreatePrivKey(conf.DataDir)
		if err != nil {
			return nil, nil, 0, errors.Wrap(err, "load or create peer ID")
		}

		if loaded {
			log.Info(ctx, "Loaded p2p key", z.Str("dir", conf.DataDir))
		} else {
			log.Info(ctx, "Generated new p2p key", z.Str("dir", conf.DataDir))
		}
	}

	localEnode, peerDB, err := p2p.NewLocalEnode(conf.P2P, p2pKey)
	if err != nil {
		return nil, nil, 0, errors.Wrap(err, "create local enode")
	}

	udpNode, err := p2p.NewUDPNode(conf.P2P, localEnode, p2pKey, manifest.ENRs())
	if err != nil {
		return nil, nil, 0, errors.Wrap(err, "start discv5 listener")
	}

	connGater, err := p2p.NewConnGater(manifest.PeerIDs())
	if err != nil {
		return nil, nil, 0, errors.Wrap(err, "connection gater")
	}

	tcpNode, err := p2p.NewTCPNode(conf.P2P, p2pKey, connGater, udpNode, manifest.Peers)
	if err != nil {
		return nil, nil, 0, errors.Wrap(err, "new p2p node", z.Str("allowlist", conf.P2P.Allowlist))
	}

	index := -1
	for i, p := range manifest.PeerIDs() {
		if tcpNode.ID() == p {
			index = i
		}
	}
	if index == -1 {
		return nil, nil, 0, errors.New("privkey not in manifest peers")
	}

	startPing := p2p.NewPingService(tcpNode, manifest.PeerIDs(), conf.TestConfig.PingCallback)

	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartP2PPing, lifecycle.HookFuncCtx(startPing))
	life.RegisterStop(lifecycle.StopP2PPeerDB, lifecycle.HookFuncMin(peerDB.Close))
	life.RegisterStop(lifecycle.StopP2PTCPNode, lifecycle.HookFuncErr(tcpNode.Close))
	life.RegisterStop(lifecycle.StopP2PUDPNode, lifecycle.HookFuncMin(udpNode.Close))

	return tcpNode, localEnode, index, nil
}

// initMonitoring returns the monitoring server providing prometheus metrics and pprof profiling.
func initMonitoring(cycle *lifecycle.Manager, addr string, localNode *enode.LocalNode) {
	mux := http.NewServeMux()

	// Serve prometheus metrics
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

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	cycle.RegisterStart(lifecycle.AsyncBackground, lifecycle.StartMonitoringAPI, httpServeHook(server.ListenAndServe))
	cycle.RegisterStop(lifecycle.StopMonitoringAPI, lifecycle.HookFunc(server.Shutdown))
}

func initValdatorAPI(life *lifecycle.Manager, conf Config) error {
	vhandler := validatorapi.Handler(nil) // TODO(corver): Construct this
	vrouter, err := validatorapi.NewRouter(vhandler, conf.BeaconNodeAddr)
	if err != nil {
		return errors.Wrap(err, "new monitoring server")
	}

	server := &http.Server{
		Addr:    conf.ValidatorAPIAddr,
		Handler: vrouter,
	}

	life.RegisterStart(lifecycle.AsyncBackground, lifecycle.StartValidatorAPI, httpServeHook(server.ListenAndServe))
	life.RegisterStop(lifecycle.StopValidatorAPI, lifecycle.HookFunc(server.Shutdown))

	return nil
}

func initTracing(life *lifecycle.Manager, conf Config) error {
	stopJeager, err := tracer.Init(tracer.WithJaegerOrNoop(conf.JaegerAddr))
	if err != nil {
		return errors.Wrap(err, "init jaeger tracing")
	}

	life.RegisterStop(lifecycle.StopTracing, lifecycle.HookFunc(stopJeager))

	return nil
}

// httpServeHook wraps a http.Server.ListenAndServe function, swallowing http.ErrServerClosed.
type httpServeHook func() error

func (h httpServeHook) Call(context.Context) error {
	err := h()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	} else if err != nil {
		return errors.Wrap(err, "serve")
	}

	return nil
}
