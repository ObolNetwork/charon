// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package app provides the top app-level abstraction and entrypoint for a charon DVC instance.
// The sub-packages also provide app-level functionality.
package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"go.uber.org/automaxprocs/maxprocs"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/k1util"
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
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/dutydb"
	"github.com/obolnetwork/charon/core/fetcher"
	"github.com/obolnetwork/charon/core/infosync"
	"github.com/obolnetwork/charon/core/leadercast"
	"github.com/obolnetwork/charon/core/parsigdb"
	"github.com/obolnetwork/charon/core/parsigex"
	"github.com/obolnetwork/charon/core/priority"
	"github.com/obolnetwork/charon/core/scheduler"
	"github.com/obolnetwork/charon/core/sigagg"
	"github.com/obolnetwork/charon/core/tracker"
	"github.com/obolnetwork/charon/core/validatorapi"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

const eth2ClientTimeout = time.Second * 2

type Config struct {
	P2P                     p2p.Config
	Log                     log.Config
	Feature                 featureset.Config
	LockFile                string
	NoVerify                bool
	PrivKeyFile             string
	MonitoringAddr          string
	ValidatorAPIAddr        string
	BeaconNodeAddrs         []string
	JaegerAddr              string
	JaegerService           string
	SimnetBMock             bool
	SimnetVMock             bool
	SimnetValidatorKeysDir  string
	SimnetSlotDuration      time.Duration
	SyntheticBlockProposals bool
	BuilderAPI              bool
	SimnetBMockFuzz         bool

	TestConfig TestConfig
}

// TestConfig defines additional test-only config.
type TestConfig struct {
	p2p.TestPingConfig

	// Lock provides the lock explicitly, skips loading from disk.
	Lock *cluster.Lock
	// P2PKey provides the p2p privkey explicitly, skips loading from keystore on disk.
	P2PKey *k1.PrivateKey
	// ParSigExFunc provides an in-memory partial signature exchange.
	ParSigExFunc func() core.ParSigEx
	// LcastTransportFunc provides an in-memory leader cast transport.
	LcastTransportFunc func() leadercast.Transport
	// SimnetKeys provides private key shares for the simnet validatormock signer.
	SimnetKeys []tbls.PrivateKey
	// SimnetBMockOpts defines additional simnet beacon mock options.
	SimnetBMockOpts []beaconmock.Option
	// BroadcastCallback is called when a duty is completed and sent to the broadcast component.
	BroadcastCallback func(context.Context, core.Duty, core.PubKey, core.SignedData) error
	// BuilderRegistration provides a channel for tests to trigger builder registration by the validator mock,
	BuilderRegistration <-chan *eth2api.VersionedValidatorRegistration
	// PrioritiseCallback is called with priority protocol results.
	PrioritiseCallback func(context.Context, core.Duty, []priority.TopicResult) error
	// TCPNodeCallback provides test logic access to the libp2p host.
	TCPNodeCallback func(host.Host)
	// LibP2POpts provide test specific libp2p options.
	LibP2POpts []libp2p.Option
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

	if err := featureset.Init(ctx, conf.Feature); err != nil {
		return err
	}

	version.LogInfo(ctx, "Charon starting")

	// Wire processes and their dependencies
	life := new(lifecycle.Manager)

	if err := wireTracing(life, conf); err != nil {
		return err
	}

	lock, err := loadLock(ctx, conf)
	if err != nil {
		return err
	}

	network, err := eth2util.ForkVersionToNetwork(lock.ForkVersion)
	if err != nil {
		network = "unknown"
	}

	p2pKey := conf.TestConfig.P2PKey
	if p2pKey == nil {
		var err error
		p2pKey, err = k1util.Load(conf.PrivKeyFile)
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

	lockHashHex := hex7(lock.LockHash)
	tcpNode, err := wireP2P(ctx, life, conf, lock, p2pKey, lockHashHex)
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
		z.Int("peers", len(lock.Operators)))

	// Metric and logging labels.
	labels := map[string]string{
		"cluster_hash":    lockHashHex,
		"cluster_name":    lock.Name,
		"cluster_peer":    p2p.PeerName(tcpNode.ID()),
		"cluster_network": network,
	}
	log.SetLokiLabels(labels)
	promRegistry, err := promauto.NewRegistry(labels)
	if err != nil {
		return err
	}

	initStartupMetrics(p2p.PeerName(tcpNode.ID()), lock.Threshold, len(lock.Operators), len(lock.Validators), network)

	eth2Cl, err := newETH2Client(ctx, conf, life, lock.Validators, lock.ForkVersion)
	if err != nil {
		return err
	}

	peerIDs, err := lock.PeerIDs()
	if err != nil {
		return err
	}

	sender := new(p2p.Sender)

	wirePeerInfo(life, tcpNode, peerIDs, lock.LockHash, sender)

	qbftDebug := newQBFTDebugger()

	// seenPubkeys channel to send seen public keys from validatorapi to monitoringapi.
	seenPubkeys := make(chan core.PubKey)
	seenPubkeysFunc := func(pk core.PubKey) {
		select {
		case <-ctx.Done():
		case seenPubkeys <- pk:
		}
	}

	vapiCalls := make(chan struct{})
	vapiCallsFunc := func() {
		select {
		case <-ctx.Done():
		case vapiCalls <- struct{}{}:
		}
	}

	pubkeys, err := getDVPubkeys(lock)
	if err != nil {
		return err
	}

	wireMonitoringAPI(ctx, life, conf.MonitoringAddr, tcpNode, eth2Cl, peerIDs,
		promRegistry, qbftDebug, pubkeys, seenPubkeys, vapiCalls)

	err = wireCoreWorkflow(ctx, life, conf, lock, nodeIdx, tcpNode, p2pKey, eth2Cl,
		peerIDs, sender, qbftDebug.AddInstance, seenPubkeysFunc, vapiCallsFunc)
	if err != nil {
		return err
	}

	// Run life cycle manager
	return life.Run(ctx)
}

// wirePeerInfo wires the peerinfo protocol.
func wirePeerInfo(life *lifecycle.Manager, tcpNode host.Host, peers []peer.ID, lockHash []byte, sender *p2p.Sender) {
	gitHash, _ := version.GitCommit()
	peerInfo := peerinfo.New(tcpNode, peers, version.Version, lockHash, gitHash, sender.SendReceive)
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartPeerInfo, lifecycle.HookFuncCtx(peerInfo.Run))
}

// wireP2P constructs the p2p tcp (libp2p) and udp (discv5) nodes and registers it with the life cycle manager.
func wireP2P(ctx context.Context, life *lifecycle.Manager, conf Config,
	lock cluster.Lock, p2pKey *k1.PrivateKey, lockHashHex string,
) (host.Host, error) {
	peerIDs, err := lock.PeerIDs()
	if err != nil {
		return nil, err
	}

	relays, err := p2p.NewRelays(ctx, conf.P2P.Relays, lockHashHex)
	if err != nil {
		return nil, err
	}

	connGater, err := p2p.NewConnGater(peerIDs, relays)
	if err != nil {
		return nil, err
	}

	// Start libp2p TCP node.
	opts := []libp2p.Option{p2p.WithBandwidthReporter(peerIDs)}
	opts = append(opts, conf.TestConfig.LibP2POpts...)

	tcpNode, err := p2p.NewTCPNode(ctx, conf.P2P, p2pKey, connGater,
		false, opts...)
	if err != nil {
		return nil, err
	}

	if conf.TestConfig.TCPNodeCallback != nil {
		conf.TestConfig.TCPNodeCallback(tcpNode)
	}

	p2p.RegisterConnectionLogger(ctx, tcpNode, peerIDs)

	life.RegisterStop(lifecycle.StopP2PTCPNode, lifecycle.HookFuncErr(tcpNode.Close))

	for _, relay := range relays {
		life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartRelay, p2p.NewRelayReserver(tcpNode, relay))
	}

	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartP2PPing, p2p.NewPingService(tcpNode, peerIDs, conf.TestConfig.TestPingConfig))
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartP2PEventCollector, p2p.NewEventCollector(tcpNode))
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartP2PRouters, p2p.NewRelayRouter(tcpNode, peerIDs, relays))

	return tcpNode, nil
}

// wireCoreWorkflow wires the core workflow components.
func wireCoreWorkflow(ctx context.Context, life *lifecycle.Manager, conf Config,
	lock cluster.Lock, nodeIdx cluster.NodeIdx, tcpNode host.Host, p2pKey *k1.PrivateKey,
	eth2Cl eth2wrap.Client, peerIDs []peer.ID, sender *p2p.Sender,
	qbftSniffer func(*pbv1.SniffedConsensusInstance), seenPubkeys func(core.PubKey),
	vapiCalls func(),
) error {
	// Convert and prep public keys and public shares
	var (
		corePubkeys                  []core.PubKey
		eth2Pubkeys                  []eth2p0.BLSPubKey
		pubshares                    []eth2p0.BLSPubKey
		allPubSharesByKey            = make(map[core.PubKey]map[int]tbls.PublicKey) // map[pubkey]map[shareIdx]pubshare
		feeRecipientAddrByCorePubkey = make(map[core.PubKey]string)
	)
	for i, dv := range lock.Validators {
		pubkey, err := dv.PublicKey()
		if err != nil {
			return err
		}

		corePubkey, err := core.PubKeyFromBytes(pubkey[:])
		if err != nil {
			return err
		}

		allPubShares := make(map[int]tbls.PublicKey)
		for i, b := range dv.PubShares {
			pubshare, err := tblsconv.PubkeyFromBytes(b)
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

		eth2Share := eth2p0.BLSPubKey(pubShare)

		eth2Pubkey := eth2p0.BLSPubKey(pubkey)

		eth2Pubkeys = append(eth2Pubkeys, eth2Pubkey)
		corePubkeys = append(corePubkeys, corePubkey)
		pubshares = append(pubshares, eth2Share)
		allPubSharesByKey[corePubkey] = allPubShares
		feeRecipientAddrByCorePubkey[corePubkey] = lock.FeeRecipientAddresses()[i]
	}

	peers, err := lock.Peers()
	if err != nil {
		return err
	}

	deadlineFunc, err := core.NewDutyDeadlineFunc(ctx, eth2Cl)
	if err != nil {
		return err
	}

	deadlinerFunc := func(label string) core.Deadliner {
		return core.NewDeadliner(ctx, label, deadlineFunc)
	}

	mutableConf := newMutableConfig(ctx, conf)

	sched, err := scheduler.New(corePubkeys, eth2Cl, mutableConf.BuilderAPI)
	if err != nil {
		return err
	}

	feeRecipientFunc := func(pubkey core.PubKey) string {
		return feeRecipientAddrByCorePubkey[pubkey]
	}

	sched.SubscribeSlots(setFeeRecipient(eth2Cl, eth2Pubkeys, feeRecipientFunc))
	sched.SubscribeSlots(tracker.NewInclDelayFunc(eth2Cl, sched.GetDutyDefinition))

	fetch, err := fetcher.New(eth2Cl, feeRecipientFunc)
	if err != nil {
		return err
	}

	dutyDB := dutydb.NewMemDB(deadlinerFunc("dutydb"))

	vapi, err := validatorapi.NewComponent(eth2Cl, allPubSharesByKey, nodeIdx.ShareIdx, feeRecipientFunc,
		mutableConf.BuilderAPI, seenPubkeys)
	if err != nil {
		return err
	}

	if err := wireVAPIRouter(life, conf.ValidatorAPIAddr, eth2Cl, vapi, vapiCalls); err != nil {
		return err
	}

	parSigDB := parsigdb.NewMemDB(lock.Threshold, deadlinerFunc("parsigdb"))

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

	aggSigDB := aggsigdb.NewMemDB(deadlinerFunc("aggsigdb"))

	broadcaster, err := bcast.New(ctx, eth2Cl)
	if err != nil {
		return err
	}

	retryer := retry.New[core.Duty](deadlineFunc)

	cons, startCons, err := newConsensus(conf, lock, tcpNode, p2pKey, sender,
		nodeIdx, deadlinerFunc("consensus"), qbftSniffer)
	if err != nil {
		return err
	}

	err = wirePrioritise(ctx, conf, life, tcpNode, peerIDs, lock.Threshold,
		sender.SendReceive, cons, sched, p2pKey, deadlineFunc, mutableConf)
	if err != nil {
		return err
	}

	wireRecaster(sched, sigAgg, broadcaster)

	track, err := newTracker(ctx, life, deadlineFunc, peers, eth2Cl)
	if err != nil {
		return err
	}
	opts := []core.WireOption{
		core.WithTracing(),
		core.WithTracking(track),
		core.WithAsyncRetry(retryer),
	}
	core.Wire(sched, fetch, cons, dutyDB, vapi, parSigDB, parSigEx, sigAgg, aggSigDB, broadcaster, opts...)

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
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartParSigDB, lifecycle.HookFuncCtx(parSigDB.Trim))
	life.RegisterStop(lifecycle.StopScheduler, lifecycle.HookFuncMin(sched.Stop))
	life.RegisterStop(lifecycle.StopDutyDB, lifecycle.HookFuncMin(dutyDB.Shutdown))
	life.RegisterStop(lifecycle.StopRetryer, lifecycle.HookFuncCtx(retryer.Shutdown))

	return nil
}

// wirePrioritise wires the priority protocol which determines cluster wide priorities for the next epoch.
func wirePrioritise(ctx context.Context, conf Config, life *lifecycle.Manager, tcpNode host.Host,
	peers []peer.ID, threshold int, sendFunc p2p.SendReceiveFunc, coreCons core.Consensus,
	sched core.Scheduler, p2pKey *k1.PrivateKey, deadlineFunc func(duty core.Duty) (time.Time, bool),
	mutableConf *mutableConfig,
) error {
	if !featureset.Enabled(featureset.Priority) {
		return nil
	}

	cons, ok := coreCons.(*consensus.Component)
	if !ok {
		// Priority protocol not supported for leader cast.
		return nil
	}

	// exchangeTimeout of 6 seconds (half a slot) is a good thumb suck.
	// It is long enough for all peers to exchange proposals both in prod and in testing.
	const exchangeTimeout = time.Second * 6

	prio, err := priority.NewComponent(ctx, tcpNode, peers, threshold,
		sendFunc, p2p.RegisterHandler, cons, exchangeTimeout, p2pKey, deadlineFunc)
	if err != nil {
		return err
	}

	isync := infosync.New(prio,
		version.Supported(),
		Protocols(),
		ProposalTypes(conf.BuilderAPI, conf.SyntheticBlockProposals),
	)

	mutableConf.SetInfoSync(isync)

	// Trigger info syncs in last slot of the epoch (for the next epoch).
	sched.SubscribeSlots(func(ctx context.Context, slot core.Slot) error {
		if !slot.LastInEpoch() {
			return nil
		}

		return isync.Trigger(ctx, slot.Slot)
	})

	if conf.TestConfig.PrioritiseCallback != nil {
		prio.Subscribe(conf.TestConfig.PrioritiseCallback)
	}

	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartPeerInfo, lifecycle.HookFuncCtx(prio.Start))

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

// newTracker creates and starts a new tracker instance.
func newTracker(ctx context.Context, life *lifecycle.Manager, deadlineFunc func(duty core.Duty) (time.Time, bool),
	peers []p2p.Peer, eth2Cl eth2wrap.Client,
) (core.Tracker, error) {
	slotDuration, err := eth2Cl.SlotDuration(ctx)
	if err != nil {
		return nil, err
	}

	analyser := core.NewDeadliner(ctx, "tracker_analyser", func(duty core.Duty) (time.Time, bool) {
		d, ok := deadlineFunc(duty)
		return d.Add(slotDuration), ok // Add one slot delay to analyser to capture duty expired errors.
	})
	deleter := core.NewDeadliner(ctx, "tracker_deleter", func(duty core.Duty) (time.Time, bool) {
		d, ok := deadlineFunc(duty)
		return d.Add(time.Minute), ok // Delete duties after deadline+1min.
	})

	trackFrom, err := calculateTrackerDelay(ctx, eth2Cl, time.Now())
	if err != nil {
		return nil, err
	}

	track := tracker.New(analyser, deleter, peers, trackFrom)
	life.RegisterStart(lifecycle.AsyncBackground, lifecycle.StartTracker, lifecycle.HookFunc(track.Run))

	return track, nil
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

		pk := eth2p0.BLSPubKey(pubkey)
		pubkeys = append(pubkeys, pk)
	}

	return pubkeys, nil
}

// newETH2Client returns a new eth2client; it is either a beaconmock for
// simnet or a multi http client to a real beacon node.
func newETH2Client(ctx context.Context, conf Config, life *lifecycle.Manager,
	validators []cluster.DistValidator, forkVersion []byte,
) (eth2wrap.Client, error) {
	pubkeys, err := eth2PubKeys(validators)
	if err != nil {
		return nil, err
	}

	// Default to 1s slot duration if not set.
	if conf.SimnetSlotDuration == 0 {
		conf.SimnetSlotDuration = time.Second
	}

	if conf.SimnetBMockFuzz {
		log.Info(ctx, "Beaconmock fuzz configured!")
		bmock, err := beaconmock.New(beaconmock.WithBeaconMockFuzzer())
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

	if conf.SimnetBMock { // Configure the beacon mock.
		const dutyFactor = 100 // Duty factor spreads duties deterministically in an epoch.
		opts := []beaconmock.Option{
			beaconmock.WithSlotDuration(conf.SimnetSlotDuration),
			beaconmock.WithDeterministicAttesterDuties(dutyFactor),
			beaconmock.WithDeterministicSyncCommDuties(2, 8), // First 2 epochs of every 8
			beaconmock.WithValidatorSet(createMockValidators(pubkeys)),
		}
		if !conf.SyntheticBlockProposals { // Only add deterministic proposals if synthetic duties are disabled.
			opts = append(opts, beaconmock.WithDeterministicProposerDuties(dutyFactor))
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

		if conf.SyntheticBlockProposals {
			log.Info(ctx, "Synthetic block proposals enabled")
			wrap = eth2wrap.WithSyntheticDuties(wrap, pubkeys)
		}

		life.RegisterStop(lifecycle.StopBeaconMock, lifecycle.HookFuncErr(bmock.Close))

		return wrap, nil
	}

	if len(conf.BeaconNodeAddrs) == 0 {
		return nil, errors.New("beacon node endpoints empty")
	}

	eth2Cl, err := eth2wrap.NewMultiHTTP(eth2ClientTimeout, conf.BeaconNodeAddrs...)
	if err != nil {
		return nil, errors.Wrap(err, "new eth2 http client")
	}

	if conf.SyntheticBlockProposals {
		log.Info(ctx, "Synthetic block proposals enabled")
		eth2Cl = eth2wrap.WithSyntheticDuties(eth2Cl, pubkeys)
	}

	// Check BN chain/network.
	schedule, err := eth2Cl.ForkSchedule(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "fetch fork schedule")
	}
	var ok bool
	for _, fork := range schedule {
		if bytes.Equal(fork.CurrentVersion[:], forkVersion) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, errors.Wrap(err, "lock file fork version not in beacon node fork schedule (probably wrong chain/network)")
	}

	return eth2Cl, nil
}

// newConsensus returns a new consensus component and its start lifecycle hook.
func newConsensus(conf Config, lock cluster.Lock, tcpNode host.Host, p2pKey *k1.PrivateKey,
	sender *p2p.Sender, nodeIdx cluster.NodeIdx, deadliner core.Deadliner,
	qbftSniffer func(*pbv1.SniffedConsensusInstance),
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
		comp, err := consensus.New(tcpNode, sender, peers, p2pKey, deadliner, qbftSniffer, featureset.Enabled(featureset.QBFTDoubleLeadTimer))
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
				EffectiveBalance:      eth2p0.Gwei(31300000000),
				PublicKey:             pubkey,
				ExitEpoch:             18446744073709551615,
				WithdrawableEpoch:     18446744073709551615,
			},
		}
	}

	return resp
}

// wireVAPIRouter constructs the validator API router and registers it with the life cycle manager.
func wireVAPIRouter(life *lifecycle.Manager, vapiAddr string, eth2Cl eth2wrap.Client,
	handler validatorapi.Handler, vapiCalls func(),
) error {
	vrouter, err := validatorapi.NewRouter(handler, eth2Cl)
	if err != nil {
		return errors.Wrap(err, "new monitoring server")
	}

	server := &http.Server{
		Addr: vapiAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			vapiCalls()
			vrouter.ServeHTTP(w, r)
		}),
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

// setFeeRecipient returns a slot subscriber for scheduler which calls prepare_beacon_proposer endpoint at start of each epoch.
// TODO(dhruv): move this somewhere else once more use-cases like this becomes clear.
func setFeeRecipient(eth2Cl eth2wrap.Client, pubkeys []eth2p0.BLSPubKey, feeRecipientFunc func(core.PubKey) string) func(ctx context.Context, slot core.Slot) error {
	onStartup := true
	var osMutex sync.Mutex

	return func(ctx context.Context, slot core.Slot) error {
		osMutex.Lock()
		// Either call if it is first slot in epoch or on charon startup.
		if !onStartup && !slot.FirstInEpoch() {
			osMutex.Unlock()
			return nil
		}
		onStartup = false
		osMutex.Unlock()

		// TODO(corver): Use cache instead of using head to try to mitigate this expensive call.
		vals, err := eth2Cl.ValidatorsByPubKey(ctx, "head", pubkeys)
		if err != nil {
			return err
		}

		var activeVals []*eth2v1.Validator
		for _, validator := range vals {
			if validator == nil {
				return errors.New("validator data cannot be nil")
			}
			if validator.Status != eth2v1.ValidatorStateActiveOngoing {
				continue
			}
			activeVals = append(activeVals, validator)
		}

		if len(activeVals) == 0 {
			return nil // No active validators.
		}

		var preps []*eth2v1.ProposalPreparation
		for _, val := range activeVals {
			if val == nil || val.Validator == nil {
				return errors.New("validator data cannot be nil")
			}

			feeRecipient := feeRecipientFunc(core.PubKeyFrom48Bytes(val.Validator.PublicKey))

			var addr bellatrix.ExecutionAddress
			b, err := hex.DecodeString(strings.TrimPrefix(feeRecipient, "0x"))
			if err != nil {
				return errors.Wrap(err, "hex decode fee recipient address")
			}
			copy(addr[:], b)

			preps = append(preps, &eth2v1.ProposalPreparation{
				ValidatorIndex: val.Index,
				FeeRecipient:   addr,
			})
		}

		return eth2Cl.SubmitProposalPreparations(ctx, preps)
	}
}

// getDVPubkeys returns DV public keys from given cluster.Lock.
func getDVPubkeys(lock cluster.Lock) ([]core.PubKey, error) {
	var pubkeys []core.PubKey
	for _, dv := range lock.Validators {
		pk, err := dv.PublicKey()
		if err != nil {
			return nil, err
		}

		pubkey, err := core.PubKeyFromBytes(pk[:])
		if err != nil {
			return nil, err
		}
		pubkeys = append(pubkeys, pubkey)
	}

	return pubkeys, nil
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

// Protocols returns the list of supported Protocols in order of precedence.
func Protocols() []protocol.ID {
	var resp []protocol.ID
	resp = append(resp, consensus.Protocols()...)
	resp = append(resp, parsigex.Protocols()...)
	resp = append(resp, peerinfo.Protocols()...)
	resp = append(resp, priority.Protocols()...)

	return resp
}

// ProposalTypes returns the local proposal types in order of precedence.
func ProposalTypes(builder bool, synthetic bool) []core.ProposalType {
	var resp []core.ProposalType
	if builder {
		resp = append(resp, core.ProposalTypeBuilder)
	}
	if synthetic {
		resp = append(resp, core.ProposalTypeSynthetic)
	}
	resp = append(resp, core.ProposalTypeFull) // Always support full as fallback.

	return resp
}

// hex7 returns the first 7 (or less) hex chars of the provided bytes.
func hex7(input []byte) string {
	resp := hex.EncodeToString(input)
	if len(resp) <= 7 {
		return resp
	}

	return resp[:7]
}
