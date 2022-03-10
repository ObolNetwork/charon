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

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/dB2510/kryptology/pkg/signatures/bls/bls_sig"
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
	"github.com/obolnetwork/charon/testutil/validatormock"
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
	// DisablePing disables the ping service.
	DisablePing bool
	// PingCallback is called when a ping was completed to a peer.
	PingCallback func(peer.ID)
	// ParSigExFunc provides an in-memory partial signature exchange.
	ParSigExFunc func() core.ParSigEx
	// LcastTransportFunc provides an in-memory leader cast transport.
	LcastTransportFunc func() leadercast.Transport
	// SimnetSecrets provides private key shares for the simnet validatormock signer.
	SimnetSecrets []*bls_sig.SecretKey
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

	log.Info(ctx, "Charon starting", z.Str("version", version.Version))

	_, _ = maxprocs.Set()
	initStartupMetrics()

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

	if err := wireValidatorAPI(life, conf); err != nil {
		return err
	}

	if err := wireSimNetCoreWorkflow(life, conf, manifest, nodeIdx, tcpNode); err != nil {
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

// wireSimNetCoreWorkflow wires a simnet core workflow including a beaconmock and validatormock.
func wireSimNetCoreWorkflow(life *lifecycle.Manager, conf Config, manifest Manifest, nodeIdx NodeIdx, tcpNode host.Host) error {
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

	// Configure the beacon mock.
	bmock := beaconmock.New(
		beaconmock.WithDefaultStaticProvider(),       // Use mostly beacon chain config.
		beaconmock.WithSlotsPerEpoch(len(pubshares)), // Except for slots per epoch, make that faster.
		beaconmock.WithSlotDuration(time.Second),     // Except for slots duration, make that faster as well.
		beaconmock.WithDeterministicDuties(13),       // This should result in pseudo random duties.
		beaconmock.WithValidatorSet(createMockValidators(pubkeys)),
	)

	sched, err := scheduler.New(corePubkeys, bmock)
	if err != nil {
		return err
	}

	fetch, err := fetcher.New(bmock)
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

	vapi, err := validatorapi.NewComponent(bmock, pubSharesByKey, nodeIdx.ShareIdx)
	if err != nil {
		return err
	}

	parSigDB := parsigdb.NewMemDB(threshold)

	var parSigEx core.ParSigEx
	if conf.TestConfig.ParSigExFunc != nil {
		parSigEx = conf.TestConfig.ParSigExFunc()
	} else {
		// TODO(corver): Use p2p implementation here.
		parSigEx = parsigex.NewMemExFunc()()
	}

	sigAgg := sigagg.New(threshold)

	broadcaster, err := bcast.New(bmock)
	if err != nil {
		return err
	}

	core.Wire(sched, fetch, consensus, dutyDB, vapi, parSigDB, parSigEx, sigAgg, broadcaster)

	err = wireValidatorMock(conf, pubshares, sched, vapi)
	if err != nil {
		return err
	}

	if conf.TestConfig.BroadcastCallback != nil {
		sigAgg.Subscribe(conf.TestConfig.BroadcastCallback)
	}

	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartLeaderCast, lifecycle.HookFunc(consensus.Run))
	life.RegisterStart(lifecycle.AsyncBackground, lifecycle.StartScheduler, lifecycle.HookFuncErr(sched.Run))
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

// wireValidatorAPI constructs the validator API and registers it with the life cycle manager.
func wireValidatorAPI(life *lifecycle.Manager, conf Config) error {
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

// wireTracing constructs the global tracer and registers it with the life cycle manager.
func wireTracing(life *lifecycle.Manager, conf Config) error {
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

func wireValidatorMock(conf Config, pubshares []eth2p0.BLSPubKey, sched core.Scheduler, vapi *validatorapi.Component) error {
	secrets := conf.TestConfig.SimnetSecrets
	// if len(secrets) == 0 {
	//	// TODO(corver): Load simnet secret shares from conf.DataDir/simnetkey*)
	//}

	signer := validatormock.NewSigner(secrets...)

	// Trigger validatormock when scheduler triggers new slot.
	sched.Subscribe(func(ctx context.Context, duty core.Duty, _ core.FetchArgSet) error {
		ctx = log.WithTopic(ctx, "validatormock")
		go func() {
			err := validatormock.Attest(ctx, vapi, signer, eth2p0.Slot(duty.Slot), pubshares...)
			if err != nil {
				log.Warn(ctx, "attestation failed", z.Err(err))
			} else {
				log.Info(ctx, "attestation success", z.I64("slot", duty.Slot))
			}
		}()

		return nil
	})

	return nil
}
