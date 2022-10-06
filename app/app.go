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

// Package app provides the top app-level abstraction and entrypoint for a charon DVC instance.
// The sub-packages also provide app-level functionality.
package app

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"net/http"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/automaxprocs/maxprocs"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/lifecycle"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/peerinfo"
	"github.com/obolnetwork/charon/app/promauto"
	"github.com/obolnetwork/charon/app/retry"
	"github.com/obolnetwork/charon/app/tracer"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/aggsigdb"
	"github.com/obolnetwork/charon/core/bcast"
	"github.com/obolnetwork/charon/core/consensus"
	"github.com/obolnetwork/charon/core/dutydb"
	"github.com/obolnetwork/charon/core/fetcher"
	"github.com/obolnetwork/charon/core/leadercast"
	"github.com/obolnetwork/charon/core/parsigdb"
	"github.com/obolnetwork/charon/core/parsigex"
	"github.com/obolnetwork/charon/core/scheduler"
	"github.com/obolnetwork/charon/core/sigagg"
	"github.com/obolnetwork/charon/core/tracker"
	"github.com/obolnetwork/charon/core/validatorapi"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

const eth2ClientTimeout = time.Second * 2

type Config struct {
	P2P                    p2p.Config
	Log                    log.Config
	Feature                featureset.Config
	LockFile               string
	NoVerify               bool
	PrivKeyFile            string
	MonitoringAddr         string
	ValidatorAPIAddr       string
	BeaconNodeAddrs        []string
	JaegerAddr             string
	JaegerService          string
	SimnetBMock            bool
	SimnetVMock            bool
	SimnetValidatorKeysDir string
	BuilderAPI             bool

	TestConfig TestConfig
}

// TestConfig defines additional test-only config.
type TestConfig struct {
	p2p.TestPingConfig

	// Lock provides the lock explicitly, skips loading from disk.
	Lock *cluster.Lock
	// P2PKey provides the p2p privkey explicitly, skips loading from keystore on disk.
	P2PKey *ecdsa.PrivateKey
	// ParSigExFunc provides an in-memory partial signature exchange.
	ParSigExFunc func() core.ParSigEx
	// LcastTransportFunc provides an in-memory leader cast transport.
	LcastTransportFunc func() leadercast.Transport
	// SimnetKeys provides private key shares for the simnet validatormock signer.
	SimnetKeys []*bls_sig.SecretKey
	// SimnetBMockOpts defines additional simnet beacon mock options.
	SimnetBMockOpts []beaconmock.Option
	// BroadcastCallback is called when a duty is completed and sent to the broadcast component.
	BroadcastCallback func(context.Context, core.Duty, core.PubKey, core.SignedData) error
	// BuilderRegistration provides a channel for tests to trigger builder registration by the validator mock,
	BuilderRegistration <-chan *eth2api.VersionedValidatorRegistration
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
	if err := log.InitLogger(conf.Log); err != nil {
		return err
	}

	if err := featureset.Init(ctx, conf.Feature); err != nil {
		return err
	}

	gitHash, gitTimestamp := version.GitCommit()
	log.Info(ctx, "Charon starting",
		z.Str("version", version.Version),
		z.Str("git_commit_hash", gitHash),
		z.Str("git_commit_time", gitTimestamp),
	)

	// Wire processes and their dependencies
	life := new(lifecycle.Manager)

	if err := wireTracing(life, conf); err != nil {
		return err
	}

	lock, err := loadLock(conf)
	if err != nil {
		return err
	}

	if err := lock.VerifySignatures(); err != nil && !conf.NoVerify {
		return errors.Wrap(err, "cluster lock signature verification failed. Run with --no-verify to bypass verification at own risk")
	} else if err != nil && conf.NoVerify {
		log.Warn(ctx, "Ignoring failed cluster lock signature verification due to --no-verify flag", err)
	}

	lockHashHex := hex.EncodeToString(lock.LockHash)[:7]

	p2pKey := conf.TestConfig.P2PKey
	if p2pKey == nil {
		var err error
		p2pKey, err = crypto.LoadECDSA(conf.PrivKeyFile)
		if err != nil {
			return errors.Wrap(err, "load priv key")
		}
	}

	peers, err := lock.Peers()
	if err != nil {
		return err
	}

	if err := p2p.VerifyP2PKey(peers, p2pKey); err != nil {
		return err
	}

	tcpNode, localEnode, err := wireP2P(ctx, life, conf, lock, p2pKey, lockHashHex)
	if err != nil {
		return err
	}

	nodeIdx, err := lock.NodeIdx(tcpNode.ID())
	if err != nil {
		return errors.Wrap(err, "private key not matching lock file")
	}

	log.Info(ctx, "Lock file loaded",
		z.Str("peer_name", p2p.PeerName(tcpNode.ID())),
		z.Int("peer_index", nodeIdx.PeerIdx),
		z.Str("cluster_hash", lockHashHex),
		z.Str("cluster_name", lock.Name),
		z.Int("peers", len(lock.Operators)),
		z.Str("enr", localEnode.Node().String()))

	promRegistry, err := promauto.NewRegistry(prometheus.Labels{
		"cluster_hash": lockHashHex,
		"cluster_name": lock.Name,
		"cluster_peer": p2p.PeerName(tcpNode.ID()),
	})
	if err != nil {
		return err
	}

	initStartupMetrics(
		p2p.PeerName(tcpNode.ID()),
		lock.Threshold,
		len(lock.Operators),
		len(lock.Validators),
		lock.ForkVersion,
	)

	eth2Cl, err := newETH2Client(ctx, conf, life, lock.Validators)
	if err != nil {
		return err
	}

	peerIDs, err := lock.PeerIDs()
	if err != nil {
		return err
	}

	sender := new(p2p.Sender)

	wirePeerInfo(life, tcpNode, peerIDs, lock.LockHash, sender)

	wireMonitoringAPI(ctx, life, conf.MonitoringAddr, localEnode, tcpNode, eth2Cl, peerIDs, promRegistry)

	if err := wireCoreWorkflow(ctx, life, conf, lock, nodeIdx, tcpNode, p2pKey, eth2Cl, peerIDs, sender); err != nil {
		return err
	}

	// Run life cycle manager
	return life.Run(ctx)
}

// wirePeerInfo wires the peerinfo protocol.
func wirePeerInfo(life *lifecycle.Manager, tcpNode host.Host, peers []peer.ID, lockHash []byte, sender *p2p.Sender) {
	peerInfo := peerinfo.New(tcpNode, peers, version.Version, lockHash, sender.SendReceive)
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartPeerInfo, lifecycle.HookFuncCtx(peerInfo.Run))
}

// wireP2P constructs the p2p tcp (libp2p) and udp (discv5) nodes and registers it with the life cycle manager.
func wireP2P(ctx context.Context, life *lifecycle.Manager, conf Config,
	lock cluster.Lock, p2pKey *ecdsa.PrivateKey, lockHashHex string,
) (host.Host, *enode.LocalNode, error) {
	peers, err := lock.Peers()
	if err != nil {
		return nil, nil, err
	}
	peerIDs, err := lock.PeerIDs()
	if err != nil {
		return nil, nil, err
	}

	localEnode, peerDB, err := p2p.NewLocalEnode(conf.P2P, p2pKey)
	if err != nil {
		return nil, nil, err
	}

	bootnodes, err := p2p.NewUDPBootnodes(ctx, conf.P2P, peers, localEnode.ID(), lockHashHex)
	if err != nil {
		return nil, nil, err
	}

	udpNode, err := p2p.NewUDPNode(ctx, conf.P2P, localEnode, p2pKey, bootnodes)
	if err != nil {
		return nil, nil, err
	}

	relays := p2p.NewRelays(conf.P2P, bootnodes)

	connGater, err := p2p.NewConnGater(peerIDs, relays)
	if err != nil {
		return nil, nil, err
	}

	tcpNode, err := p2p.NewTCPNode(conf.P2P, p2pKey, connGater)
	if err != nil {
		return nil, nil, err
	}

	life.RegisterStop(lifecycle.StopP2PPeerDB, lifecycle.HookFuncMin(peerDB.Close))
	life.RegisterStop(lifecycle.StopP2PTCPNode, lifecycle.HookFuncErr(tcpNode.Close))
	life.RegisterStop(lifecycle.StopP2PUDPNode, lifecycle.HookFuncMin(udpNode.Close))

	for _, relay := range relays {
		life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartRelay, p2p.NewRelayReserver(tcpNode, relay))
	}

	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartP2PPing, p2p.NewPingService(tcpNode, peerIDs, conf.TestConfig.TestPingConfig))
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartP2PEventCollector, p2p.NewEventCollector(tcpNode))
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartP2PRouters, p2p.NewDiscoveryRouter(tcpNode, udpNode, peers))
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartP2PRouters, p2p.NewRelayRouter(tcpNode, peers, relays))

	return tcpNode, localEnode, nil
}

// wireCoreWorkflow wires the core workflow components.
func wireCoreWorkflow(ctx context.Context, life *lifecycle.Manager, conf Config,
	lock cluster.Lock, nodeIdx cluster.NodeIdx, tcpNode host.Host, p2pKey *ecdsa.PrivateKey,
	eth2Cl eth2wrap.Client, peerIDs []peer.ID, sender *p2p.Sender,
) error {
	// Convert and prep public keys and public shares
	var (
		corePubkeys       []core.PubKey
		pubshares         []eth2p0.BLSPubKey
		pubSharesByKey    = make(map[*bls_sig.PublicKey]*bls_sig.PublicKey)
		allPubSharesByKey = make(map[core.PubKey]map[int]*bls_sig.PublicKey) // map[pubkey]map[shareIdx]pubshare
	)
	for _, dv := range lock.Validators {
		pubkey, err := dv.PublicKey()
		if err != nil {
			return err
		}

		corePubkey, err := tblsconv.KeyToCore(pubkey)
		if err != nil {
			return err
		}

		allPubShares := make(map[int]*bls_sig.PublicKey)
		for i, b := range dv.PubShares {
			pubshare, err := tblsconv.KeyFromBytes(b)
			if err != nil {
				return err
			}

			// share index is 1-indexed
			allPubShares[i+1] = pubshare
		}

		pubShare, err := dv.PublicShare(nodeIdx.PeerIdx)
		if err != nil {
			return err
		}

		eth2Share, err := tblsconv.KeyToETH2(pubShare)
		if err != nil {
			return err
		}

		corePubkeys = append(corePubkeys, corePubkey)
		pubSharesByKey[pubkey] = pubShare
		pubshares = append(pubshares, eth2Share)
		allPubSharesByKey[corePubkey] = allPubShares
	}

	peers, err := lock.Peers()
	if err != nil {
		return err
	}

	deadlineFunc, err := core.NewDutyDeadlineFunc(ctx, eth2Cl)
	if err != nil {
		return err
	}

	deadlinerFunc := func() core.Deadliner {
		return core.NewDeadliner(ctx, deadlineFunc)
	}

	sched, err := scheduler.New(corePubkeys, eth2Cl, conf.BuilderAPI)
	if err != nil {
		return err
	}

	fetch, err := fetcher.New(eth2Cl)
	if err != nil {
		return err
	}

	dutyDB := dutydb.NewMemDB(deadlinerFunc())

	vapi, err := validatorapi.NewComponent(eth2Cl, pubSharesByKey, nodeIdx.ShareIdx, lock.FeeRecipientAddress)
	if err != nil {
		return err
	}

	if err := wireVAPIRouter(life, conf.ValidatorAPIAddr, eth2Cl, vapi); err != nil {
		return err
	}

	parSigDB := parsigdb.NewMemDB(lock.Threshold)

	var parSigEx core.ParSigEx
	if conf.TestConfig.ParSigExFunc != nil {
		parSigEx = conf.TestConfig.ParSigExFunc()
	} else {
		verifyFunc, err := parsigex.NewEth2Verifier(eth2Cl, allPubSharesByKey)
		if err != nil {
			return err
		}

		parSigEx = parsigex.NewParSigEx(tcpNode, sender.SendAsync, nodeIdx.PeerIdx, peerIDs, verifyFunc)
	}

	sigAgg := sigagg.New(lock.Threshold)

	aggSigDB := aggsigdb.NewMemDB()

	broadcaster, err := bcast.New(ctx, eth2Cl)
	if err != nil {
		return err
	}

	retryer, err := retry.New[core.Duty](deadlineFunc)
	if err != nil {
		return err
	}

	cons, startCons, err := newConsensus(conf, lock, tcpNode, p2pKey, sender, nodeIdx, deadlinerFunc())
	if err != nil {
		return err
	}

	if err := wireTracker(ctx, life, deadlineFunc, peers, eth2Cl, sched, fetch, cons, vapi, parSigDB, parSigEx, sigAgg); err != nil {
		return err
	}

	wireRecaster(sched, sigAgg, broadcaster)

	core.Wire(sched, fetch, cons, dutyDB, vapi,
		parSigDB, parSigEx, sigAgg, aggSigDB, broadcaster,
		core.WithTracing(),
		core.WithAsyncRetry(retryer),
	)

	err = wireValidatorMock(conf, pubshares, sched)
	if err != nil {
		return err
	}

	if conf.TestConfig.BroadcastCallback != nil {
		sigAgg.Subscribe(conf.TestConfig.BroadcastCallback)
	}

	life.RegisterStart(lifecycle.AsyncBackground, lifecycle.StartScheduler, lifecycle.HookFuncErr(sched.Run))
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartP2PConsensus, startCons)
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartAggSigDB, lifecycle.HookFuncCtx(aggSigDB.Run))
	life.RegisterStop(lifecycle.StopScheduler, lifecycle.HookFuncMin(sched.Stop))
	life.RegisterStop(lifecycle.StopDutyDB, lifecycle.HookFuncMin(dutyDB.Shutdown))
	life.RegisterStop(lifecycle.StopRetryer, lifecycle.HookFuncCtx(retryer.Shutdown))

	return nil
}

// wireRecaster wires the rebroadcaster component to scheduler, sigAgg and broadcaster.
// This is not done in core.Wire since recaster isn't really part of the official core workflow (yet).
func wireRecaster(sched core.Scheduler, sigAgg core.SigAgg, broadcaster core.Broadcaster) {
	recaster := bcast.NewRecaster()
	sched.SubscribeSlots(recaster.SlotTicked)
	sigAgg.Subscribe(recaster.Store)
	recaster.Subscribe(broadcaster.Broadcast)
}

// wireTracker creates a new tracker instance and wires it to the components with "output events".
func wireTracker(ctx context.Context, life *lifecycle.Manager, deadlineFunc func(duty core.Duty) (time.Time, bool),
	peers []p2p.Peer, ethCl eth2wrap.Client,
	sched core.Scheduler, fetcher core.Fetcher, cons core.Consensus, vapi core.ValidatorAPI,
	parSigDB core.ParSigDB, parSigEx core.ParSigEx, sigAgg core.SigAgg,
) error {
	analyser := core.NewDeadliner(ctx, deadlineFunc)
	deleter := core.NewDeadliner(ctx, func(duty core.Duty) (time.Time, bool) {
		d, ok := deadlineFunc(duty)
		if !ok {
			return d, false
		}

		// To delete duties after 2 * deadline.
		return d.Add(time.Until(d)), true
	})

	trackFrom, err := calculateTrackerDelay(ctx, ethCl, time.Now())
	if err != nil {
		return err
	}

	trackr := tracker.New(analyser, deleter, peers, trackFrom)

	sched.SubscribeDuties(trackr.SchedulerEvent)
	fetcher.Subscribe(trackr.FetcherEvent)
	cons.Subscribe(trackr.ConsensusEvent)
	vapi.Subscribe(trackr.ValidatorAPIEvent)
	parSigDB.SubscribeInternal(trackr.ParSigDBInternalEvent)
	parSigDB.SubscribeThreshold(trackr.ParSigDBThresholdEvent)
	parSigEx.Subscribe(trackr.ParSigExEvent)
	sigAgg.Subscribe(trackr.SigAggEvent)

	life.RegisterStart(lifecycle.AsyncBackground, lifecycle.StartTracker, lifecycle.HookFunc(trackr.Run))

	return nil
}

// calculateTrackerDelay returns the slot to start tracking from. This mitigates noisy failed duties on
// startup due to downstream VC startup delays.
func calculateTrackerDelay(ctx context.Context, cl eth2wrap.Client, now time.Time) (int64, error) {
	const maxDelayTime = time.Second * 10 // We want to delay at most 10 seconds
	const minDelaySlots = 2               // But we do not want to delay less than 2 slots

	genesisTime, err := cl.GenesisTime(ctx)
	if err != nil {
		return 0, err
	}
	slotDuration, err := cl.SlotDuration(ctx)
	if err != nil {
		return 0, err
	}

	currentSlot := int64(now.Sub(genesisTime) / slotDuration)

	maxDelayTimeSlot := currentSlot + int64(maxDelayTime/slotDuration) + 1
	minDelaySlot := currentSlot + minDelaySlots

	if maxDelayTimeSlot < minDelaySlot {
		return minDelaySlot, nil
	}

	return maxDelayTimeSlot, nil
}

// eth2PubKeys returns a list of BLS pubkeys of validators in the cluster lock.
func eth2PubKeys(validators []cluster.DistValidator) ([]eth2p0.BLSPubKey, error) {
	var pubkeys []eth2p0.BLSPubKey

	for _, dv := range validators {
		pubkey, err := dv.PublicKey()
		if err != nil {
			return []eth2p0.BLSPubKey{}, err
		}

		pk, err := tblsconv.KeyToETH2(pubkey)
		if err != nil {
			return []eth2p0.BLSPubKey{}, err
		}

		pubkeys = append(pubkeys, pk)
	}

	return pubkeys, nil
}

// newETH2Client returns a new eth2client; it is either a beaconmock for
// simnet or a multi http client to a real beacon node.
func newETH2Client(ctx context.Context, conf Config, life *lifecycle.Manager,
	validators []cluster.DistValidator,
) (eth2wrap.Client, error) {
	pubkeys, err := eth2PubKeys(validators)
	if err != nil {
		return nil, err
	}

	if conf.SimnetBMock { // Configure the beacon mock.
		const dutyFactor = 100 // Duty factor spreads duties deterministicly in an epoch.
		opts := []beaconmock.Option{
			beaconmock.WithSlotDuration(time.Second),
			beaconmock.WithDeterministicAttesterDuties(dutyFactor),
			beaconmock.WithDeterministicProposerDuties(dutyFactor),
			beaconmock.WithValidatorSet(createMockValidators(pubkeys)),
		}
		opts = append(opts, conf.TestConfig.SimnetBMockOpts...)
		bmock, err := beaconmock.New(opts...)
		if err != nil {
			return nil, err
		}

		wrap, err := eth2wrap.Instrument(bmock)
		if err != nil {
			return nil, err
		}

		life.RegisterStop(lifecycle.StopBeaconMock, lifecycle.HookFuncErr(bmock.Close))

		return wrap, nil
	}

	if len(conf.BeaconNodeAddrs) == 0 {
		return nil, errors.New("beacon node endpoints empty")
	}

	eth2Cl, err := eth2wrap.NewMultiHTTP(ctx, eth2ClientTimeout, conf.BeaconNodeAddrs...)
	if err != nil {
		return nil, errors.Wrap(err, "new eth2 http client")
	}

	return eth2Cl, nil
}

// newConsensus returns a new consensus component and its start lifecycle hook.
func newConsensus(conf Config, lock cluster.Lock, tcpNode host.Host, p2pKey *ecdsa.PrivateKey,
	sender *p2p.Sender, nodeIdx cluster.NodeIdx, deadliner core.Deadliner,
) (core.Consensus, lifecycle.IHookFunc, error) {
	peers, err := lock.Peers()
	if err != nil {
		return nil, nil, err
	}
	peerIDs, err := lock.PeerIDs()
	if err != nil {
		return nil, nil, err
	}

	if featureset.Enabled(featureset.QBFTConsensus) {
		comp, err := consensus.New(tcpNode, sender, peers, p2pKey, deadliner)
		if err != nil {
			return nil, nil, err
		}

		return comp, lifecycle.HookFuncCtx(comp.Start), nil
	}

	var lcastTransport leadercast.Transport
	if conf.TestConfig.LcastTransportFunc != nil {
		lcastTransport = conf.TestConfig.LcastTransportFunc()
	} else {
		// TODO(corver): Either deprecate leadercast or refactor it to use p2p.Sender (and protobufs).
		lcastTransport = leadercast.NewP2PTransport(tcpNode, nodeIdx.PeerIdx, peerIDs)
	}

	lcast := leadercast.New(lcastTransport, nodeIdx.PeerIdx, len(peerIDs))

	return lcast, lifecycle.HookFuncCtx(lcast.Run), nil
}

// createMockValidators creates mock validators identified by their public shares.
func createMockValidators(pubkeys []eth2p0.BLSPubKey) beaconmock.ValidatorSet {
	resp := make(beaconmock.ValidatorSet)
	for i, pubkey := range pubkeys {
		vIdx := eth2p0.ValidatorIndex(i)

		resp[vIdx] = &eth2v1.Validator{
			Balance: eth2p0.Gwei(31300000000),
			Index:   vIdx,
			Status:  eth2v1.ValidatorStateActiveOngoing,
			Validator: &eth2p0.Validator{
				WithdrawalCredentials: []byte("12345678901234567890123456789012"),
				PublicKey:             pubkey,
			},
		}
	}

	return resp
}

// wireVAPIRouter constructs the validator API router and registers it with the life cycle manager.
func wireVAPIRouter(life *lifecycle.Manager, vapiAddr string, eth2Cl eth2wrap.Client, handler validatorapi.Handler) error {
	vrouter, err := validatorapi.NewRouter(handler, eth2Cl)
	if err != nil {
		return errors.Wrap(err, "new monitoring server")
	}

	server := &http.Server{
		Addr:              vapiAddr,
		Handler:           vrouter,
		ReadHeaderTimeout: time.Second,
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
