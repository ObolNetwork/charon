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

	eth2client "github.com/attestantio/go-eth2-client"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
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
	"github.com/obolnetwork/charon/core/aggsigdb"
	"github.com/obolnetwork/charon/core/bcast"
	"github.com/obolnetwork/charon/core/dutydb"
	"github.com/obolnetwork/charon/core/fetcher"
	"github.com/obolnetwork/charon/core/leadercast"
	"github.com/obolnetwork/charon/core/parsigdb"
	"github.com/obolnetwork/charon/core/parsigex"
	"github.com/obolnetwork/charon/core/scheduler"
	"github.com/obolnetwork/charon/core/sigagg"
	"github.com/obolnetwork/charon/core/validatorapi"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil/beaconmock"
	"github.com/obolnetwork/charon/testutil/keystore"
	"github.com/obolnetwork/charon/testutil/validatormock"
)

type Config struct {
	P2P              p2p.Config
	Log              log.Config
	ManifestFile     string
	DataDir          string
	MonitoringAddr   string
	ValidatorAPIAddr string
	BeaconNodeAddr   string
	JaegerAddr       string
	JaegerService    string
	SimnetBMock      bool
	SimnetVMock      bool

	TestConfig TestConfig
}

// TestConfig defines additional test-only config.
type TestConfig struct {
	// Manifest provides the manifest explicitly, skips loading ManifestFile from disk.
	Manifest *Manifest
	// P2PKey provides the p2p privkey explicitly, skips loading from keystore on disk.
	P2PKey *ecdsa.PrivateKey
	// DisablePing disables the ping service.
	DisablePing bool
	// PingCallback is called when a ping was completed to a peer.
	PingCallback func(peer.ID)
	// ParSigExFunc provides an in-memory partial signature exchange.
	ParSigExFunc func() core.ParSigEx
	// LcastTransportFunc provides an in-memory leader cast transport.
	LcastTransportFunc func() leadercast.Transport
	// SimnetKeys provides private key shares for the simnet validatormock signer.
	SimnetKeys []*bls_sig.SecretKey
	// SimnetBMockOpts defines additional simnet beacon mock options.
	SimnetBMockOpts []beaconmock.Option
	// BroadcastCallback is called when a duty is completed and sent to the broadcast component.
	BroadcastCallback func(context.Context, core.Duty, core.PubKey, core.AggSignedData) error
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

	_, _ = maxprocs.Set()
	initStartupMetrics()
	if err := log.InitLogger(conf.Log); err != nil {
		return err
	}

	log.Info(ctx, "Charon starting", z.Str("version", version.Version))

	// Wire processes and their dependencies
	life := new(lifecycle.Manager)

	if err := wireTracing(life, conf); err != nil {
		return err
	}

	manifest, err := loadManifest(conf)
	if err != nil {
		return err
	}

	tcpNode, localEnode, err := wireP2P(ctx, life, conf, manifest)
	if err != nil {
		return err
	}

	nodeIdx, err := manifest.NodeIdx(tcpNode.ID())
	if err != nil {
		return err
	}

	log.Info(ctx, "Manifest loaded",
		z.Int("peers", len(manifest.Peers)),
		z.Str("peer_id", p2p.ShortID(tcpNode.ID())),
		z.Int("peer_index", nodeIdx.PeerIdx))

	wireMonitoringAPI(life, conf.MonitoringAddr, localEnode)

	if err := wireCoreWorkflow(ctx, life, conf, manifest, nodeIdx, tcpNode); err != nil {
		return err
	}

	// Run life cycle manager
	return life.Run(ctx)
}

// wireP2P constructs the p2p tcp (libp2p) and udp (discv5) nodes and registers it with the life cycle manager.
func wireP2P(ctx context.Context, life *lifecycle.Manager, conf Config, manifest Manifest,
) (host.Host, *enode.LocalNode, error) {
	p2pKey := conf.TestConfig.P2PKey
	if p2pKey == nil {
		var err error
		var loaded bool
		p2pKey, loaded, err = p2p.LoadOrCreatePrivKey(conf.DataDir)
		if err != nil {
			return nil, nil, errors.Wrap(err, "load or create peer ID")
		}

		if loaded {
			log.Info(ctx, "Loaded p2p key", z.Str("dir", conf.DataDir))
		} else {
			log.Info(ctx, "Generated new p2p key", z.Str("dir", conf.DataDir))
		}
	}

	localEnode, peerDB, err := p2p.NewLocalEnode(conf.P2P, p2pKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "create local enode")
	}

	udpNode, err := p2p.NewUDPNode(conf.P2P, localEnode, p2pKey, manifest.ENRs())
	if err != nil {
		return nil, nil, errors.Wrap(err, "start discv5 listener")
	}

	connGater, err := p2p.NewConnGater(manifest.PeerIDs())
	if err != nil {
		return nil, nil, errors.Wrap(err, "connection gater")
	}

	tcpNode, err := p2p.NewTCPNode(conf.P2P, p2pKey, connGater, udpNode, manifest.Peers)
	if err != nil {
		return nil, nil, errors.Wrap(err, "new p2p node", z.Str("allowlist", conf.P2P.Allowlist))
	}

	if !conf.TestConfig.DisablePing {
		startPing := p2p.NewPingService(tcpNode, manifest.PeerIDs(), conf.TestConfig.PingCallback)

		life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartP2PPing, lifecycle.HookFuncCtx(startPing))
	}

	life.RegisterStop(lifecycle.StopP2PPeerDB, lifecycle.HookFuncMin(peerDB.Close))
	life.RegisterStop(lifecycle.StopP2PTCPNode, lifecycle.HookFuncErr(tcpNode.Close))
	life.RegisterStop(lifecycle.StopP2PUDPNode, lifecycle.HookFuncMin(udpNode.Close))

	return tcpNode, localEnode, nil
}

// wireCoreWorkflow wires the core workflow components.
//nolint:cyclop,revive
func wireCoreWorkflow(ctx context.Context, life *lifecycle.Manager, conf Config, manifest Manifest, nodeIdx NodeIdx, tcpNode host.Host) error {
	// Convert and prep public keys and public shares
	var (
		corePubkeys    []core.PubKey
		pubkeys        []eth2p0.BLSPubKey
		pubshares      []eth2p0.BLSPubKey
		pubSharesByKey = make(map[*bls_sig.PublicKey]*bls_sig.PublicKey)
		threshold      int
	)
	for _, dv := range manifest.DVs {
		threshold = dv.Threshold()

		corePubkey, err := tblsconv.KeyToCore(dv.PublicKey())
		if err != nil {
			return err
		}

		pubkey, err := tblsconv.KeyToETH2(dv.PublicKey())
		if err != nil {
			return err
		}

		pubShare, err := dv.PublicShare(nodeIdx.ShareIdx)
		if err != nil {
			return err
		}

		eth2Share, err := tblsconv.KeyToETH2(pubShare)
		if err != nil {
			return err
		}

		corePubkeys = append(corePubkeys, corePubkey)
		pubkeys = append(pubkeys, pubkey)
		pubSharesByKey[dv.PublicKey()] = pubShare
		pubshares = append(pubshares, eth2Share)
	}

	// Configure the beacon node api.
	var eth2Cl eth2client.Service
	if conf.SimnetBMock {
		// Configure the beacon mock.
		opts := []beaconmock.Option{
			beaconmock.WithSlotDuration(time.Second),
			beaconmock.WithDeterministicDuties(100),
			// TODO(dhruv): remove this when DutyProposer is in place
			beaconmock.WithNoProposerDuties(),
			beaconmock.WithValidatorSet(createMockValidators(pubkeys)),
		}
		opts = append(opts, conf.TestConfig.SimnetBMockOpts...)
		bmock, err := beaconmock.New(opts...)
		if err != nil {
			return err
		}
		conf.BeaconNodeAddr = bmock.HTTPAddr()
		eth2Cl = bmock
		life.RegisterStop(lifecycle.StopBeaconMock, lifecycle.HookFuncErr(bmock.Close))
	} else {
		var err error
		eth2Cl, err = eth2http.New(ctx,
			eth2http.WithLogLevel(1),
			eth2http.WithAddress(conf.BeaconNodeAddr),
		)
		if err != nil {
			return errors.Wrap(err, "new eth2 http client")
		}
	}

	sched, err := scheduler.New(corePubkeys, eth2Cl)
	if err != nil {
		return err
	}

	fetch, err := fetcher.New(eth2Cl)
	if err != nil {
		return err
	}

	var lcastTransport leadercast.Transport
	if conf.TestConfig.LcastTransportFunc != nil {
		lcastTransport = conf.TestConfig.LcastTransportFunc()
	} else {
		lcastTransport = leadercast.NewP2PTransport(tcpNode, nodeIdx.PeerIdx, manifest.PeerIDs())
	}

	consensus := leadercast.New(lcastTransport, nodeIdx.PeerIdx, len(manifest.PeerIDs()))

	dutyDB := dutydb.NewMemDB()

	vapi, err := validatorapi.NewComponent(eth2Cl, pubSharesByKey, nodeIdx.ShareIdx)
	if err != nil {
		return err
	}

	if err := wireVAPIRouter(life, conf, vapi); err != nil {
		return err
	}

	parSigDB := parsigdb.NewMemDB(threshold)

	var parSigEx core.ParSigEx
	if conf.TestConfig.ParSigExFunc != nil {
		parSigEx = conf.TestConfig.ParSigExFunc()
	} else {
		parSigEx = parsigex.NewParSigEx(tcpNode, nodeIdx.PeerIdx, manifest.PeerIDs())
	}

	sigAgg := sigagg.New(threshold)

	aggSigDB := aggsigdb.NewMemDB()

	broadcaster, err := bcast.New(eth2Cl)
	if err != nil {
		return err
	}

	core.Wire(sched, fetch, consensus, dutyDB, vapi, parSigDB, parSigEx, sigAgg, aggSigDB, broadcaster)

	err = wireValidatorMock(conf, pubshares, sched)
	if err != nil {
		return err
	}

	if conf.TestConfig.BroadcastCallback != nil {
		sigAgg.Subscribe(conf.TestConfig.BroadcastCallback)
	}

	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartLeaderCast, lifecycle.HookFunc(consensus.Run))
	life.RegisterStart(lifecycle.AsyncBackground, lifecycle.StartScheduler, lifecycle.HookFuncErr(sched.Run))
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartAggSigDB, lifecycle.HookFuncCtx(aggSigDB.Run))
	life.RegisterStop(lifecycle.StopScheduler, lifecycle.HookFuncMin(sched.Stop))

	return nil
}

// createMockValidators creates mock validators identified by their public shares.
func createMockValidators(pubkeys []eth2p0.BLSPubKey) beaconmock.ValidatorSet {
	resp := make(beaconmock.ValidatorSet)
	for i, pubkey := range pubkeys {
		vIdx := eth2p0.ValidatorIndex(i)

		resp[vIdx] = &eth2v1.Validator{
			Index:  vIdx,
			Status: eth2v1.ValidatorStateActiveOngoing,
			Validator: &eth2p0.Validator{
				WithdrawalCredentials: []byte("12345678901234567890123456789012"),
				PublicKey:             pubkey,
			},
		}
	}

	return resp
}

// wireMonitoringAPI constructs the monitoring API and registers it with the life cycle manager.
// It serves prometheus metrics, pprof profiling and the runtime enr.
func wireMonitoringAPI(life *lifecycle.Manager, addr string, localNode *enode.LocalNode) {
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

	life.RegisterStart(lifecycle.AsyncBackground, lifecycle.StartMonitoringAPI, httpServeHook(server.ListenAndServe))
	life.RegisterStop(lifecycle.StopMonitoringAPI, lifecycle.HookFunc(server.Shutdown))
}

// wireVAPIRouter constructs the validator API router and registers it with the life cycle manager.
func wireVAPIRouter(life *lifecycle.Manager, conf Config, handler validatorapi.Handler) error {
	vrouter, err := validatorapi.NewRouter(handler, conf.BeaconNodeAddr)
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

// wireTracing constructs the global tracer and registers it with the life cycle manager.
func wireTracing(life *lifecycle.Manager, conf Config) error {
	stopjaeger, err := tracer.Init(
		tracer.WithJaegerOrNoop(conf.JaegerAddr),
		tracer.WithJaegerService(conf.JaegerService),
	)
	if err != nil {
		return errors.Wrap(err, "init jaeger tracing")
	}

	life.RegisterStop(lifecycle.StopTracing, lifecycle.HookFunc(stopjaeger))

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

// wireValidatorMock wires the validator mock if enabled. The validator mock attestions
// will be triggered by scheduler's DutyAttester. It connects via http validatorapi.Router.
func wireValidatorMock(conf Config, pubshares []eth2p0.BLSPubKey, sched core.Scheduler) error {
	if !conf.SimnetBMock || !conf.SimnetVMock {
		return nil
	}

	secrets := conf.TestConfig.SimnetKeys
	if len(secrets) == 0 {
		var err error
		secrets, err = keystore.LoadSimnetKeys(conf.DataDir)
		if err != nil {
			return err
		}
	}

	signer := validatormock.NewSigner(secrets...)

	// Trigger validatormock when scheduler triggers new slot.
	sched.Subscribe(func(ctx context.Context, duty core.Duty, _ core.FetchArgSet) error {
		if duty.Type != core.DutyAttester {
			return nil
		}

		ctx = log.WithTopic(ctx, "vmock")
		go func() {
			addr := "http://" + conf.ValidatorAPIAddr
			cl, err := eth2http.New(ctx, eth2http.WithLogLevel(1), eth2http.WithAddress(addr))
			if err != nil {
				log.Warn(ctx, "Cannot connect to validatorapi", z.Err(err))
				return
			}

			err = validatormock.Attest(ctx, cl.(*eth2http.Service), signer, eth2p0.Slot(duty.Slot), pubshares...)
			if err != nil {
				log.Warn(ctx, "Attestation failed", z.Err(err))
			} else {
				log.Info(ctx, "Attestation success", z.I64("slot", duty.Slot))
			}
		}()

		return nil
	})

	return nil
}
