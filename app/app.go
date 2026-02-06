// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/automaxprocs/maxprocs"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth1wrap"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/lifecycle"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/peerinfo"
	"github.com/obolnetwork/charon/app/privkeylock"
	"github.com/obolnetwork/charon/app/promauto"
	"github.com/obolnetwork/charon/app/retry"
	"github.com/obolnetwork/charon/app/sse"
	"github.com/obolnetwork/charon/app/stacksnipe"
	"github.com/obolnetwork/charon/app/tracer"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/aggsigdb"
	"github.com/obolnetwork/charon/core/bcast"
	"github.com/obolnetwork/charon/core/consensus"
	"github.com/obolnetwork/charon/core/consensus/protocols"
	"github.com/obolnetwork/charon/core/consensus/qbft"
	"github.com/obolnetwork/charon/core/dutydb"
	"github.com/obolnetwork/charon/core/fetcher"
	"github.com/obolnetwork/charon/core/infosync"
	"github.com/obolnetwork/charon/core/parsigdb"
	"github.com/obolnetwork/charon/core/parsigex"
	"github.com/obolnetwork/charon/core/priority"
	"github.com/obolnetwork/charon/core/scheduler"
	"github.com/obolnetwork/charon/core/sigagg"
	"github.com/obolnetwork/charon/core/tracker"
	"github.com/obolnetwork/charon/core/validatorapi"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil/beaconmock" // Allow testutil
)

type Config struct {
	P2P                         p2p.Config
	Log                         log.Config
	Feature                     featureset.Config
	ManifestFile                string
	LockFile                    string
	NoVerify                    bool
	PrivKeyFile                 string
	PrivKeyLocking              bool
	MonitoringAddr              string
	DebugAddr                   string
	ValidatorAPIAddr            string
	BeaconNodeAddrs             []string
	BeaconNodeTimeout           time.Duration
	BeaconNodeSubmitTimeout     time.Duration
	JaegerAddr                  string
	JaegerService               string
	OTLPAddress                 string
	OTLPHeaders                 []string
	OTLPInsecure                bool
	OTLPServiceName             string
	SimnetBMock                 bool
	SimnetVMock                 bool
	SimnetValidatorKeysDir      string
	SimnetSlotDuration          time.Duration
	SyntheticBlockProposals     bool
	BuilderAPI                  bool
	SimnetBMockFuzz             bool
	TestnetConfig               eth2util.Network
	ProcDirectory               string
	ConsensusProtocol           string
	Nickname                    string
	BeaconNodeHeaders           []string
	TargetGasLimit              uint
	FallbackBeaconNodeAddrs     []string
	ExecutionEngineAddr         string
	Graffiti                    []string
	GraffitiDisableClientAppend bool
	VCTLSCertFile               string
	VCTLSKeyFile                string

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
	// SimnetKeys provides private key shares for the simnet validatormock signer.
	SimnetKeys []tbls.PrivateKey
	// SimnetBMockOpts defines additional simnet beacon mock options.
	SimnetBMockOpts []beaconmock.Option
	// BroadcastCallback is called when a duty is completed and sent to the broadcast component.
	BroadcastCallback func(context.Context, core.Duty, core.SignedDataSet) error
	// PrioritiseCallback is called with priority protocol results.
	PrioritiseCallback func(context.Context, core.Duty, []priority.TopicResult) error
	// P2PNodeCallback provides test logic access to the libp2p host.
	P2PNodeCallback func(host.Host)
	// LibP2POpts provide test specific libp2p options.
	LibP2POpts []libp2p.Option
	// P2PFuzz enables peer to peer fuzzing of charon nodes in a cluster.
	// If enabled, this node will send fuzzed data over p2p to its peers in the cluster.
	P2PFuzz bool
}

// Run is the entrypoint for running a charon DVC instance.
// All processes and their dependencies are wired and added
// to the life cycle manager which handles starting and graceful shutdown.
func Run(ctx context.Context, conf Config) (err error) {
	ctx = log.WithTopic(ctx, "app-start")

	_, _ = maxprocs.Set()

	if err := featureset.Init(ctx, conf.Feature); err != nil {
		return err
	}

	version.LogInfo(ctx, "Charon starting")

	// Wire processes and their dependencies
	life := new(lifecycle.Manager)

	if conf.PrivKeyLocking {
		lockSvc, err := privkeylock.New(conf.PrivKeyFile, conf.LockFile, "charon run")
		if err != nil {
			return err
		}

		life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartPrivkeyLock, lifecycle.HookFuncErr(lockSvc.Run))
		life.RegisterStop(lifecycle.StopPrivkeyLock, lifecycle.HookFuncMin(lockSvc.Close))
	}

	stackSniper := stacksnipe.New(conf.ProcDirectory, stackComponents)
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartStackSnipe, lifecycle.HookFuncCtx(stackSniper.Run))

	if conf.TestnetConfig.IsNonZero() {
		eth2util.AddTestNetwork(conf.TestnetConfig)
	}

	eth1Cl := eth1wrap.NewDefaultEthClientRunner(conf.ExecutionEngineAddr)
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartEth1Client, lifecycle.HookFuncCtx(eth1Cl.Run))

	lock, err := loadClusterLock(ctx, conf, eth1Cl)
	if err != nil {
		return err
	}

	core.SetClusterHash(lock.LockHash)

	if err := wireTracing(life, conf, lock.LockHash); err != nil {
		return err
	}

	network, err := eth2util.ForkVersionToNetwork(lock.ForkVersion)
	if err != nil {
		network = "unknown"
	}

	// For Gnosis/Chiado we automatically enable GnosisBlockHotfix feature.
	if network == eth2util.Chiado.Name || network == eth2util.Gnosis.Name {
		// Even though we alter the feature flag post Init() call,
		// this shall be safe for the GnosisBlockHotfix feature flag.
		// We don't expect any serialization to happen in between.
		featureset.EnableGnosisBlockHotfixIfNotDisabled(ctx, conf.Feature)
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

	lockHashHex := Hex7(lock.LockHash)

	// Create prometheus registry early so it can be used by p2p.
	// Metric and logging labels.
	labels := map[string]string{
		"cluster_hash":    lockHashHex,
		"cluster_name":    lock.Name,
		"cluster_peer":    "", // Set below from p2p key
		"nickname":        conf.Nickname,
		"cluster_network": network,
		"charon_version":  version.Version.String(),
	}

	// Derive peer ID from private key to set cluster_peer label before registering metrics
	peerID, err := p2p.PeerIDFromKey(p2pKey.PubKey())
	if err != nil {
		return err
	}

	labels["cluster_peer"] = p2p.PeerName(peerID)

	// Update cluster_peer label for Loki
	log.SetLokiLabels(labels)

	promRegistry, err := promauto.NewRegistry(labels)
	if err != nil {
		return err
	}

	p2pNode, err := wireP2P(ctx, life, conf, lock, p2pKey, lockHashHex, lock.UUID, promRegistry, labels)
	if err != nil {
		return err
	}

	nodeIdx, err := lock.NodeIdx(p2pNode.ID())
	if err != nil {
		return errors.Wrap(err, "private key not matching cluster manifest file")
	}

	enrRec, err := enr.New(p2pKey)
	if err != nil {
		return errors.Wrap(err, "creating enr record from privkey")
	}

	log.Info(ctx, "Lock file loaded",
		z.Str("peer_name", p2p.PeerName(p2pNode.ID())),
		z.Str("nickname", conf.Nickname),
		z.Int("peer_index", nodeIdx.PeerIdx),
		z.Str("cluster_name", lock.Name),
		z.Str("cluster_hash", lockHashHex),
		z.Str("cluster_hash_full", hex.EncodeToString(lock.LockHash)),
		z.Str("enr", enrRec.String()),
		z.Int("peers", len(lock.Operators)))

	initStartupMetrics(p2p.PeerName(p2pNode.ID()), lock.Threshold, len(lock.Operators), len(lock.Validators), network)

	eth2Cl, subEth2Cl, err := newETH2Client(ctx, conf, life, lock, lock.ForkVersion, conf.BeaconNodeTimeout, conf.BeaconNodeSubmitTimeout)
	if err != nil {
		return err
	}

	sseListener, err := sse.StartListener(ctx, eth2Cl, conf.BeaconNodeAddrs, conf.BeaconNodeHeaders)
	if err != nil {
		return err
	}

	peerIDs, err := lock.PeerIDs()
	if err != nil {
		return err
	}

	// Enable p2p fuzzing if --p2p-fuzz is set.
	if conf.TestConfig.P2PFuzz {
		p2p.SetFuzzerDefaultsUnsafe()
	}

	sender := new(p2p.Sender)

	if len(conf.Nickname) > 32 {
		return errors.New("nickname cannot exceed 32 characters")
	}

	wirePeerInfo(life, p2pNode, peerIDs, lock.LockHash, sender, conf.BuilderAPI, conf.Nickname)

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

	consensusDebugger := consensus.NewDebugger()

	wireMonitoringAPI(ctx, life, conf.MonitoringAddr, conf.DebugAddr, p2pNode, eth2Cl, conf.BeaconNodeAddrs, peerIDs,
		promRegistry, consensusDebugger, pubkeys, seenPubkeys, vapiCalls, len(lock.Validators))

	err = wireCoreWorkflow(ctx, life, conf, lock, nodeIdx, p2pNode, p2pKey, eth2Cl, subEth2Cl,
		peerIDs, sender, consensusDebugger, pubkeys, seenPubkeysFunc, sseListener, vapiCallsFunc)
	if err != nil {
		return err
	}

	// Run life cycle manager
	return life.Run(ctx)
}

// wirePeerInfo wires the peerinfo protocol.
func wirePeerInfo(life *lifecycle.Manager, p2pNode host.Host, peers []peer.ID, lockHash []byte, sender *p2p.Sender, builderEnabled bool, nickname string) {
	gitHash, _ := version.GitCommit()
	peerInfo := peerinfo.New(p2pNode, peers, version.Version, lockHash, gitHash, sender.SendReceive, builderEnabled, nickname)
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartPeerInfo, lifecycle.HookFuncCtx(peerInfo.Run))
}

// wireP2P constructs the p2p tcp or udp (libp2p) nodes and registers it with the life cycle manager.
func wireP2P(ctx context.Context, life *lifecycle.Manager, conf Config,
	lock *cluster.Lock, p2pKey *k1.PrivateKey, lockHashHex, uuid string, promRegistry *prometheus.Registry, labels prometheus.Labels,
) (host.Host, error) {
	peerIDs, err := lock.PeerIDs()
	if err != nil {
		return nil, err
	}

	relays, err := p2p.NewRelays(ctx, conf.P2P.Relays, lockHashHex, uuid)
	if err != nil {
		return nil, err
	}

	connGater, err := p2p.NewConnGater(peerIDs, relays)
	if err != nil {
		return nil, err
	}

	// Start libp2p node.
	bwOpt, bwReporter := p2p.WithBandwidthReporter(peerIDs)

	// Wrap registerer with cluster labels for libp2p metrics
	wrappedRegisterer := prometheus.WrapRegistererWith(labels, promRegistry)
	swarmOpts := []swarm.Option{p2p.WithSwarmMetrics(wrappedRegisterer)}

	opts := []libp2p.Option{
		bwOpt,
		libp2p.ResourceManager(new(network.NullResourceManager)),
	}
	opts = append(opts, conf.TestConfig.LibP2POpts...)

	var p2pNode host.Host
	if featureset.Enabled(featureset.QUIC) {
		p2pNode, err = p2p.NewNode(ctx, conf.P2P, p2pKey, connGater, false, p2p.NodeTypeQUIC, swarmOpts, opts...)
	} else {
		p2pNode, err = p2p.NewNode(ctx, conf.P2P, p2pKey, connGater, false, p2p.NodeTypeTCP, swarmOpts, opts...)
	}

	if err != nil {
		return nil, err
	}

	// Register host with bandwidth reporter for transport protocol detection
	p2p.RegisterBandwidthReporter(bwReporter, p2pNode)

	if conf.TestConfig.P2PNodeCallback != nil {
		conf.TestConfig.P2PNodeCallback(p2pNode)
	}

	p2p.RegisterConnectionLogger(ctx, p2pNode, peerIDs)

	life.RegisterStop(lifecycle.StopP2PNode, lifecycle.HookFuncErr(p2pNode.Close))

	for _, relay := range relays {
		life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartRelay, p2p.NewRelayReserver(p2pNode, relay))
	}

	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartP2PPing, p2p.NewPingService(p2pNode, peerIDs, conf.TestConfig.TestPingConfig))
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartP2PEventCollector, p2p.NewEventCollector(p2pNode))
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartP2PRouters, p2p.NewRelayRouter(p2pNode, peerIDs, relays))
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartForceDirectConns, p2p.ForceDirectConnections(p2pNode, peerIDs))
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartForceQUICConns, p2p.UpgradeToQUICConnections(p2pNode, peerIDs))

	return p2pNode, nil
}

// wireCoreWorkflow wires the core workflow components.
func wireCoreWorkflow(ctx context.Context, life *lifecycle.Manager, conf Config,
	lock *cluster.Lock, nodeIdx cluster.NodeIdx, p2pNode host.Host, p2pKey *k1.PrivateKey,
	eth2Cl, submissionEth2Cl eth2wrap.Client, peerIDs []peer.ID, sender *p2p.Sender,
	consensusDebugger consensus.Debugger, pubkeys []core.PubKey, seenPubkeys func(core.PubKey),
	sseListener sse.Listener, vapiCalls func(),
) error {
	// Convert and prep public keys and public shares
	var (
		builderRegistrations         []*eth2api.VersionedSignedValidatorRegistration
		eth2Pubkeys                  []eth2p0.BLSPubKey
		pubshares                    []eth2p0.BLSPubKey
		allPubSharesByKey            = make(map[core.PubKey]map[int]tbls.PublicKey) // map[pubkey]map[shareIdx]pubshare
		feeRecipientAddrByCorePubkey = make(map[core.PubKey]string)
		lockFeeRecipientAddresses    = lock.FeeRecipientAddresses()
	)

	for vi, val := range lock.Validators {
		corePubkey, err := core.PubKeyFromBytes(val.PubKey)
		if err != nil {
			return err
		}

		allPubShares := make(map[int]tbls.PublicKey)

		for i, b := range val.PubShares {
			pubshare, err := tblsconv.PubkeyFromBytes(b)
			if err != nil {
				return err
			}

			// share index is 1-indexed
			allPubShares[i+1] = pubshare
		}

		pubShare, err := val.PublicShare(nodeIdx.PeerIdx)
		if err != nil {
			return err
		}

		eth2Share := eth2p0.BLSPubKey(pubShare)

		eth2Pubkey := eth2p0.BLSPubKey(val.PubKey)

		eth2Pubkeys = append(eth2Pubkeys, eth2Pubkey)
		pubshares = append(pubshares, eth2Share)
		allPubSharesByKey[corePubkey] = allPubShares
		feeRecipientAddrByCorePubkey[corePubkey] = lockFeeRecipientAddresses[vi]

		builderRegistration, err := val.Eth2Registration()
		if err != nil {
			return errors.Wrap(err, "convert builder registration")
		}

		builderRegistrations = append(builderRegistrations, builderRegistration)
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

	sched, err := scheduler.New(builderRegistrations, eth2Cl, conf.BuilderAPI)
	if err != nil {
		return err
	}

	sseListener.SubscribeChainReorgEvent(sched.HandleChainReorgEvent)
	sseListener.SubscribeBlockEvent(sched.HandleBlockEvent)

	feeRecipientFunc := func(pubkey core.PubKey) string {
		return feeRecipientAddrByCorePubkey[pubkey]
	}
	sched.SubscribeSlots(setFeeRecipient(eth2Cl, feeRecipientFunc))

	// Setup validator cache, refreshing it every epoch.
	valCache := eth2wrap.NewValidatorCache(eth2Cl, eth2Pubkeys)
	eth2Cl.SetValidatorCache(valCache.GetByHead)

	firstCacheRefresh := true
	refreshedBySlot := true

	// Setup duties cache, refreshing it every epoch.
	dutiesCache := eth2wrap.NewDutiesCache(eth2Cl)
	eth2Cl.SetDutiesCache(dutiesCache.ProposerDutiesCache, dutiesCache.AttesterDutiesCache, dutiesCache.SyncCommDutiesCache)
	sseListener.SubscribeChainReorgEvent(dutiesCache.InvalidateCache)

	var fvcrLock sync.RWMutex

	shouldUpdateCache := func(slot core.Slot, lock *sync.RWMutex) bool {
		lock.RLock()
		defer lock.RUnlock()

		if !slot.FirstInEpoch() && !firstCacheRefresh && refreshedBySlot {
			return false
		}

		return true
	}

	sched.SubscribeSlots(func(ctx context.Context, slot core.Slot) error {
		if !shouldUpdateCache(slot, &fvcrLock) {
			return nil
		}

		fvcrLock.Lock()
		defer fvcrLock.Unlock()

		ctx = log.WithCtx(ctx, z.Bool("first_refresh", firstCacheRefresh))

		log.Info(ctx, "Refreshing validator cache")

		// If not refreshed by slot previously then fetch the first slot of the epoch
		var slotToFetch uint64
		if !refreshedBySlot {
			slotToFetch = slot.Epoch() * slot.SlotsPerEpoch
		} else {
			slotToFetch = slot.Slot
		}

		valCache.Trim()
		if !featureset.Enabled(featureset.DisableDutiesCache) {
			dutiesCache.Trim(eth2p0.Epoch(slot.Epoch()))
		}

		_, _, refresh, err := valCache.GetBySlot(ctx, slotToFetch)
		if err != nil {
			log.Error(ctx, "Failed to refresh validator cache", err)
			return err
		}

		refreshedBySlot = refresh
		firstCacheRefresh = false

		return nil
	})

	gaterFunc, err := core.NewDutyGater(ctx, eth2Cl)
	if err != nil {
		return err
	}

	graffitiBuilder, err := fetcher.NewGraffitiBuilder(pubkeys, conf.Graffiti, conf.GraffitiDisableClientAppend, eth2Cl)
	if err != nil {
		return err
	}

	forkSchedule, err := eth2wrap.FetchForkConfig(ctx, eth2Cl)
	if err != nil {
		return err
	}

	_, slotsPerEpoch, err := eth2wrap.FetchSlotsConfig(ctx, eth2Cl)
	if err != nil {
		return err
	}

	electraSlot := eth2p0.Slot(uint64(forkSchedule[eth2wrap.Electra].Epoch) * slotsPerEpoch)

	fetch, err := fetcher.New(eth2Cl, feeRecipientFunc, conf.BuilderAPI, graffitiBuilder, electraSlot, featureset.Enabled(featureset.FetchOnlyCommIdx0))
	if err != nil {
		return err
	}

	dutyDB := dutydb.NewMemDB(deadlinerFunc("dutydb"))

	vapi, err := validatorapi.NewComponent(eth2Cl, allPubSharesByKey, nodeIdx.ShareIdx, feeRecipientFunc, conf.BuilderAPI, lock.TargetGasLimit, seenPubkeys)
	if err != nil {
		return err
	}

	if err := wireVAPIRouter(life, conf.ValidatorAPIAddr, vapi, vapiCalls, &conf); err != nil {
		return err
	}

	var (
		slotDuration uint64
		genesisTime  time.Time
	)

	if conf.TestnetConfig.IsNonZero() {
		slotDuration = 12
		genesisTime = time.Unix(conf.TestnetConfig.GenesisTimestamp, 0)
	} else {
		network, err := eth2util.ForkVersionToNetwork(lock.ForkVersion)
		if err != nil {
			network = "mainnet"
		}

		slotDuration, err = eth2util.NetworkToSlotDuration(network)
		if err != nil {
			return err
		}

		genesisTime, err = eth2util.NetworkToGenesisTime(network)
		if err != nil {
			return err
		}
	}

	parSigDB := parsigdb.NewMemDB(lock.Threshold, deadlinerFunc("parsigdb"), parsigdb.NewMemDBMetadata(slotDuration, genesisTime))

	var parSigEx core.ParSigEx
	if conf.TestConfig.ParSigExFunc != nil {
		parSigEx = conf.TestConfig.ParSigExFunc()
	} else {
		verifyFunc, err := parsigex.NewEth2Verifier(eth2Cl, allPubSharesByKey)
		if err != nil {
			return err
		}

		parSigEx = parsigex.NewParSigEx(p2pNode, sender.SendAsync, nodeIdx.PeerIdx, peerIDs, verifyFunc, gaterFunc)
	}

	sigAgg, err := sigagg.New(lock.Threshold, sigagg.NewVerifier(eth2Cl))
	if err != nil {
		return err
	}

	var aggSigDB core.AggSigDB
	if featureset.Enabled(featureset.AggSigDBV2) {
		aggSigDB = aggsigdb.NewMemDBV2(deadlinerFunc("aggsigdb"))
	} else {
		aggSigDB = aggsigdb.NewMemDB(deadlinerFunc("aggsigdb"))
	}

	submissionEth2Cl.SetValidatorCache(valCache.GetByHead)

	broadcaster, err := bcast.New(ctx, submissionEth2Cl)
	if err != nil {
		return err
	}

	retryer := retry.New(deadlineFunc)

	// Consensus
	consensusController, err := consensus.NewConsensusController(
		ctx, eth2Cl, p2pNode, sender, peers, p2pKey,
		deadlineFunc, gaterFunc, consensusDebugger, featureset.Enabled(featureset.ChainSplitHalt))
	if err != nil {
		return err
	}

	defaultConsensus := consensusController.DefaultConsensus()
	startConsensusCtrl := lifecycle.HookFuncCtx(consensusController.Start)

	coreConsensus := consensusController.CurrentConsensus() // initially points to DefaultConsensus()

	// Priority protocol always uses QBFTv2.
	err = wirePrioritise(ctx, conf, life, p2pNode, peerIDs, lock.Threshold,
		sender.SendReceive, defaultConsensus, sched, p2pKey, deadlineFunc,
		consensusController, lock.ConsensusProtocol)
	if err != nil {
		return err
	}

	track, err := newTracker(ctx, life, deadlineFunc, peers, eth2Cl)
	if err != nil {
		return err
	}

	inclusion, err := tracker.NewInclusion(ctx, eth2Cl, track.InclusionChecked)
	if err != nil {
		return err
	}

	// Core always uses the "current" consensus that is changed dynamically.
	opts := []core.WireOption{
		core.WithTracing(),
		core.WithTracking(track, inclusion),
		core.WithAsyncRetry(retryer),
	}
	core.Wire(sched, fetch, coreConsensus, dutyDB, vapi, parSigDB, parSigEx, sigAgg, aggSigDB, broadcaster, opts...)

	err = wireValidatorMock(ctx, conf, eth2Cl, pubshares, sched)
	if err != nil {
		return err
	}

	if conf.TestConfig.BroadcastCallback != nil {
		sigAgg.Subscribe(conf.TestConfig.BroadcastCallback)
	}

	life.RegisterStart(lifecycle.AsyncBackground, lifecycle.StartScheduler, lifecycle.HookFuncErr(sched.Run))
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartP2PConsensus, startConsensusCtrl)
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartAggSigDB, lifecycle.HookFuncCtx(aggSigDB.Run))
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartParSigDB, lifecycle.HookFuncCtx(parSigDB.Trim))
	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartTracker, lifecycle.HookFuncCtx(inclusion.Run))
	life.RegisterStop(lifecycle.StopScheduler, lifecycle.HookFuncMin(sched.Stop))
	life.RegisterStop(lifecycle.StopDutyDB, lifecycle.HookFuncMin(dutyDB.Shutdown))
	life.RegisterStop(lifecycle.StopRetryer, lifecycle.HookFuncCtx(retryer.Shutdown))

	return nil
}

// wirePrioritise wires the priority protocol which determines cluster wide priorities for the next epoch.
func wirePrioritise(ctx context.Context, conf Config, life *lifecycle.Manager, p2pNode host.Host,
	peers []peer.ID, threshold int, sendFunc p2p.SendReceiveFunc, coreCons core.Consensus,
	sched core.Scheduler, p2pKey *k1.PrivateKey, deadlineFunc func(duty core.Duty) (time.Time, bool),
	consensusController core.ConsensusController, clusterPreferredProtocol string,
) error {
	cons, ok := coreCons.(*qbft.Consensus)
	if !ok {
		// Priority protocol not supported for leader cast.
		return nil
	}

	// exchangeTimeout of 6 seconds (half a slot) is a good thumb suck.
	// It is long enough for all peers to exchange proposals both in prod and in testing.
	const exchangeTimeout = time.Second * 6

	prio, err := priority.NewComponent(ctx, p2pNode, peers, threshold,
		sendFunc, p2p.RegisterHandler, cons, exchangeTimeout, p2pKey, deadlineFunc)
	if err != nil {
		return err
	}

	// The initial protocols order as defined by implementation is altered by:
	// 1. Prioritizing the cluster (lock) preferred protocol to the top.
	// 2. Prioritizing the protocol specified by CLI flag (cluster run) to the top.
	// In all cases this prioritizes all versions of the protocol identified by name.
	// The order of all these operations are important.
	allProtocols := Protocols()
	if clusterPreferredProtocol != "" {
		allProtocols = protocols.PrioritizeProtocolsByName(clusterPreferredProtocol, allProtocols)
	}

	if conf.ConsensusProtocol != "" {
		allProtocols = protocols.PrioritizeProtocolsByName(conf.ConsensusProtocol, allProtocols)
	}

	isync := infosync.New(prio,
		version.Supported(),
		allProtocols,
		ProposalTypes(conf.BuilderAPI, conf.SyntheticBlockProposals),
	)

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

	prio.Subscribe(func(ctx context.Context, _ core.Duty, tr []priority.TopicResult) error {
		for _, t := range tr {
			if t.Topic == infosync.TopicProtocol {
				allProtocols := t.PrioritiesOnly()
				preferredConsensusProtocol := protocols.MostPreferredConsensusProtocol(allProtocols)
				preferredConsensusProtocolID := protocol.ID(preferredConsensusProtocol)

				if err := consensusController.SetCurrentConsensusForProtocol(ctx, preferredConsensusProtocolID); err != nil {
					log.Error(ctx, "Failed to set current consensus protocol", err, z.Str("protocol", preferredConsensusProtocol))
				} else {
					log.Info(ctx, "Current consensus protocol changed", z.Str("protocol", preferredConsensusProtocol))
				}

				break
			}
		}

		return nil
	})

	life.RegisterStart(lifecycle.AsyncAppCtx, lifecycle.StartPeerInfo, lifecycle.HookFuncCtx(prio.Start))

	return nil
}

// newTracker creates and starts a new tracker instance.
func newTracker(ctx context.Context, life *lifecycle.Manager, deadlineFunc func(duty core.Duty) (time.Time, bool),
	peers []p2p.Peer, eth2Cl eth2wrap.Client,
) (core.Tracker, error) {
	slotDuration, _, err := eth2wrap.FetchSlotsConfig(ctx, eth2Cl)
	if err != nil {
		return nil, err
	}

	// Add InclMissedLag slots and InclCheckLag delay to analyser to capture missed inclusion errors.
	trackerDelay := tracker.InclMissedLag + tracker.InclCheckLag

	analyser := core.NewDeadliner(ctx, "tracker_analyser", func(duty core.Duty) (time.Time, bool) {
		d, ok := deadlineFunc(duty)
		return d.Add(time.Duration(trackerDelay) * slotDuration), ok
	})
	deleter := core.NewDeadliner(ctx, "tracker_deleter", func(duty core.Duty) (time.Time, bool) {
		d, ok := deadlineFunc(duty)
		return d.Add(time.Duration(trackerDelay) * slotDuration).Add(time.Minute), ok // Delete duties after analyser_deadline+1min.
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
func calculateTrackerDelay(ctx context.Context, cl eth2wrap.Client, now time.Time) (uint64, error) {
	const maxDelayTime = time.Second * 10 // We want to delay at most 10 seconds

	const minDelaySlots = 2 // But we do not want to delay less than 2 slots

	genesisTime, err := eth2wrap.FetchGenesisTime(ctx, cl)
	if err != nil {
		return 0, err
	}

	slotDuration, _, err := eth2wrap.FetchSlotsConfig(ctx, cl)
	if err != nil {
		return 0, err
	}

	currentSlot := uint64(now.Sub(genesisTime) / slotDuration)

	maxDelayTimeSlot := currentSlot + uint64(maxDelayTime/slotDuration) + 1
	minDelaySlot := currentSlot + minDelaySlots

	if maxDelayTimeSlot < minDelaySlot {
		return minDelaySlot, nil
	}

	return maxDelayTimeSlot, nil
}

// eth2PubKeys returns a list of BLS pubkeys of validators in the cluster lock.
func eth2PubKeys(lock *cluster.Lock) []eth2p0.BLSPubKey {
	var pubkeys []eth2p0.BLSPubKey

	for _, dv := range lock.Validators {
		pk := eth2p0.BLSPubKey(dv.PubKey)
		pubkeys = append(pubkeys, pk)
	}

	return pubkeys
}

// newETH2Client returns a new eth2client for the configured timeouts; it is either a beaconmock for
// simnet or a multi http client to a real beacon node.
func newETH2Client(ctx context.Context, conf Config, life *lifecycle.Manager, lock *cluster.Lock, forkVersion []byte, bnTimeout time.Duration, submissionBnTimeout time.Duration) (eth2Cl eth2wrap.Client, submissionEth2Cl eth2wrap.Client, err error) {
	pubkeys := eth2PubKeys(lock)

	// Default to 1s slot duration if not set.
	if conf.SimnetSlotDuration == 0 {
		conf.SimnetSlotDuration = time.Second
	}

	if conf.SimnetBMockFuzz {
		log.Info(ctx, "Beaconmock fuzz configured!")

		bmock, err := beaconmock.New(ctx, beaconmock.WithBeaconMockFuzzer(), beaconmock.WithForkVersion([4]byte(forkVersion)))
		if err != nil {
			return nil, nil, err
		}

		beaconNodeHeaders, err := eth2util.ParseHTTPHeaders(conf.BeaconNodeHeaders)
		if err != nil {
			return nil, nil, err
		}

		fb := eth2wrap.NewSimnetFallbacks(bnTimeout, [4]byte(forkVersion), beaconNodeHeaders, conf.FallbackBeaconNodeAddrs)

		wrap, err := eth2wrap.Instrument([]eth2wrap.Client{bmock}, fb)
		if err != nil {
			return nil, nil, err
		}

		life.RegisterStop(lifecycle.StopBeaconMock, lifecycle.HookFuncErr(bmock.Close))

		return wrap, nil, nil
	}

	if conf.SimnetBMock { // Configure the beacon mock.
		genesisTime, err := eth2util.ForkVersionToGenesisTime(forkVersion)
		if err != nil {
			return nil, nil, err
		}

		const dutyFactor = 100 // Duty factor spreads duties deterministically in an epoch.

		opts := []beaconmock.Option{
			beaconmock.WithSlotDuration(conf.SimnetSlotDuration),
			beaconmock.WithGenesisTime(genesisTime),
			beaconmock.WithDeterministicAttesterDuties(dutyFactor),
			beaconmock.WithDeterministicSyncCommDuties(2, 8), // First 2 epochs of every 8
			beaconmock.WithValidatorSet(createMockValidators(pubkeys)),
		}
		if !conf.SyntheticBlockProposals { // Only add deterministic proposals if synthetic duties are disabled.
			opts = append(opts, beaconmock.WithDeterministicProposerDuties(dutyFactor))
		}

		opts = append(opts, conf.TestConfig.SimnetBMockOpts...)

		bmock, err := beaconmock.New(ctx, opts...)
		if err != nil {
			return nil, nil, err
		}

		beaconNodeHeaders, err := eth2util.ParseHTTPHeaders(conf.BeaconNodeHeaders)
		if err != nil {
			return nil, nil, err
		}

		fb := eth2wrap.NewSimnetFallbacks(bnTimeout, [4]byte(forkVersion), beaconNodeHeaders, conf.FallbackBeaconNodeAddrs)

		wrap, err := eth2wrap.Instrument([]eth2wrap.Client{bmock}, fb)
		if err != nil {
			return nil, nil, err
		}

		if conf.SyntheticBlockProposals {
			log.Info(ctx, "Synthetic block proposals enabled")

			wrap = eth2wrap.WithSyntheticDuties(wrap)
		}

		life.RegisterStop(lifecycle.StopBeaconMock, lifecycle.HookFuncErr(bmock.Close))

		return wrap, wrap, nil
	}

	if len(conf.BeaconNodeAddrs) == 0 {
		return nil, nil, errors.New("beacon node endpoints empty")
	}

	if conf.SyntheticBlockProposals {
		log.Info(ctx, "Synthetic block proposals enabled")
	}

	beaconNodeHeaders, err := eth2util.ParseHTTPHeaders(conf.BeaconNodeHeaders)
	if err != nil {
		return nil, nil, err
	}

	eth2Cl, err = configureEth2Client(ctx, forkVersion, conf.FallbackBeaconNodeAddrs, conf.BeaconNodeAddrs, beaconNodeHeaders, bnTimeout, conf.SyntheticBlockProposals)
	if err != nil {
		return nil, nil, errors.Wrap(err, "new eth2 http client")
	}

	submissionEth2Cl, err = configureEth2Client(ctx, forkVersion, conf.FallbackBeaconNodeAddrs, conf.BeaconNodeAddrs, beaconNodeHeaders, submissionBnTimeout, conf.SyntheticBlockProposals)
	if err != nil {
		return nil, nil, errors.Wrap(err, "new submission eth2 http client")
	}

	return eth2Cl, submissionEth2Cl, nil
}

// configureEth2Client configures a beacon node client with the provided settings.
func configureEth2Client(ctx context.Context, forkVersion []byte, fallbackAddrs []string, addrs []string, headers map[string]string, timeout time.Duration, syntheticBlockProposals bool) (eth2wrap.Client, error) {
	eth2Cl, err := eth2wrap.NewMultiHTTP(timeout, [4]byte(forkVersion), headers, addrs, fallbackAddrs)
	if err != nil {
		return nil, errors.Wrap(err, "new eth2 http client")
	}

	if syntheticBlockProposals {
		eth2Cl = eth2wrap.WithSyntheticDuties(eth2Cl)
	}

	// Check BN chain/network.
	eth2Resp, err := eth2Cl.ForkSchedule(ctx, &eth2api.ForkScheduleOpts{})
	if err != nil {
		return nil, errors.Wrap(err, "fetch fork schedule")
	}

	schedule := eth2Resp.Data

	var ok bool

	for _, fork := range schedule {
		if bytes.Equal(fork.CurrentVersion[:], forkVersion) {
			ok = true
			break
		}
	}

	if !ok {
		lockNetwork, err := eth2util.ForkVersionToNetwork(forkVersion)
		if err != nil {
			return nil, errors.New("cannot parse lock file fork version")
		}

		bnNetwork, err := eth2util.ForkVersionToNetwork(schedule[0].CurrentVersion[:])
		if err != nil {
			return nil, errors.New("cannot parse network current fork version")
		}

		return nil, errors.New(
			"mismatch between lock file fork version and beacon node fork schedule. Ensure the beacon node is on the correct network",
			z.Str("beacon_node", bnNetwork),
			z.Str("lock_file", lockNetwork),
		)
	}

	return eth2Cl, nil
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
func wireVAPIRouter(life *lifecycle.Manager, vapiAddr string,
	handler validatorapi.Handler, vapiCalls func(), conf *Config,
) error {
	vrouter, err := validatorapi.NewRouter(handler, conf.BuilderAPI)
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

	if conf.VCTLSCertFile != "" && conf.VCTLSKeyFile != "" {
		listenAndServeTLS := func() error {
			return server.ListenAndServeTLS(conf.VCTLSCertFile, conf.VCTLSKeyFile)
		}
		life.RegisterStart(lifecycle.AsyncBackground, lifecycle.StartValidatorAPI, httpServeHook(listenAndServeTLS))
	} else {
		life.RegisterStart(lifecycle.AsyncBackground, lifecycle.StartValidatorAPI, httpServeHook(server.ListenAndServe))
	}

	life.RegisterStop(lifecycle.StopValidatorAPI, lifecycle.HookFunc(server.Shutdown))

	return nil
}

// wireTracing constructs the global tracer and registers it with the life cycle manager.
// If OTLPAddress is not configured, no tracer is created.
func wireTracing(life *lifecycle.Manager, conf Config, clusterHash []byte) error {
	if conf.OTLPAddress == "" {
		return nil
	}

	otlpHeaders, err := eth2util.ParseHTTPHeaders(conf.OTLPHeaders)
	if err != nil {
		return err
	}

	stopTracer, err := tracer.Init(
		tracer.WithOTLPTracer(conf.OTLPAddress, otlpHeaders, conf.OTLPInsecure),
		tracer.WithServiceName(conf.OTLPServiceName),
		tracer.WithNamespaceName(Hex7(clusterHash)),
	)
	if err != nil {
		return errors.Wrap(err, "init tracing")
	}

	life.RegisterStop(lifecycle.StopTracing, lifecycle.HookFunc(stopTracer))

	return nil
}

// setFeeRecipient returns a slot subscriber for scheduler which calls prepare_beacon_proposer endpoint at start of each epoch.
func setFeeRecipient(eth2Cl eth2wrap.Client, feeRecipientFunc func(core.PubKey) string) func(ctx context.Context, slot core.Slot) error {
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

		vals, err := eth2Cl.ActiveValidators(ctx)
		if err != nil {
			return err
		}

		if len(vals) == 0 {
			return nil // No active validators.
		}

		var preps []*eth2v1.ProposalPreparation

		for vIdx, pubkey := range vals {
			feeRecipient := feeRecipientFunc(core.PubKeyFrom48Bytes(pubkey))

			var addr bellatrix.ExecutionAddress

			b, err := hex.DecodeString(strings.TrimPrefix(feeRecipient, "0x"))
			if err != nil {
				return errors.Wrap(err, "hex decode fee recipient address")
			}

			copy(addr[:], b)

			preps = append(preps, &eth2v1.ProposalPreparation{
				ValidatorIndex: vIdx,
				FeeRecipient:   addr,
			})
		}

		return eth2Cl.SubmitProposalPreparations(ctx, preps)
	}
}

// getDVPubkeys returns DV public keys from given cluster.Lock.
func getDVPubkeys(lock *cluster.Lock) ([]core.PubKey, error) {
	var pubkeys []core.PubKey

	for _, dv := range lock.Validators {
		pubkey, err := core.PubKeyFromBytes(dv.PubKey)
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

	resp = append(resp, protocols.Protocols()...)
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
