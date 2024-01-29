// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/url"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/app/peerinfo"
	"github.com/obolnetwork/charon/app/privkeylock"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/dkg/bcast"
	"github.com/obolnetwork/charon/dkg/sync"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/eth2util/keymanager"
	"github.com/obolnetwork/charon/eth2util/registration"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

type Config struct {
	DefFile       string
	NoVerify      bool
	DataDir       string
	P2P           p2p.Config
	Log           log.Config
	ShutdownDelay time.Duration

	KeymanagerAddr      string
	KeymanagerAuthToken string

	PublishAddr string
	Publish     bool

	TestConfig TestConfig
}

// TestConfig defines additional test-only config for DKG.
type TestConfig struct {
	// Def provides the cluster definition explicitly, skips loading from disk.
	Def *cluster.Definition
	// P2PKey provides the p2p privkey explicitly, skips loading from disk.
	P2PKey           *k1.PrivateKey
	SyncCallback     func(connected int, id peer.ID)
	StoreKeysFunc    func(secrets []tbls.PrivateKey, dir string) error
	TCPNodeCallback  func(host.Host)
	ShutdownCallback func()
	SyncOpts         []func(*sync.Client)
}

// HasTestConfig returns true if any of the test config fields are set.
func (c Config) HasTestConfig() bool {
	return c.TestConfig.StoreKeysFunc != nil || c.TestConfig.SyncCallback != nil || c.TestConfig.Def != nil || c.TestConfig.TCPNodeCallback != nil
}

// Run executes a dkg ceremony and writes secret share keystore and cluster lock files as output to disk.
//
//nolint:maintidx // Refactor into smaller steps.
func Run(ctx context.Context, conf Config) (err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ctx = log.WithTopic(ctx, "dkg")

	{
		// Setup private key locking.
		lockSvc, err := privkeylock.New(p2p.KeyPath(conf.DataDir)+".lock", "charon dkg")
		if err != nil {
			return err
		}

		// Start it async
		go func() {
			if err := lockSvc.Run(); err != nil {
				log.Error(ctx, "Error locking private key file", err)
			}
		}()

		// Stop it on exit.
		defer lockSvc.Close()
	}

	version.LogInfo(ctx, "Charon DKG starting")

	def, err := loadDefinition(ctx, conf)
	if err != nil {
		return err
	}

	// This DKG only supports a few specific config versions.
	if def.Version != "v1.6.0" && def.Version != "v1.7.0" {
		return errors.New("only v1.6.0 and v1.7.0 cluster definition version supported")
	}

	if err := validateKeymanagerFlags(ctx, conf.KeymanagerAddr, conf.KeymanagerAuthToken); err != nil {
		return err
	}

	// Check if keymanager address is reachable.
	if conf.KeymanagerAddr != "" {
		cl := keymanager.New(conf.KeymanagerAddr, conf.KeymanagerAuthToken)
		if err = cl.VerifyConnection(ctx); err != nil {
			return errors.Wrap(err, "verify keymanager address")
		}
	}

	if !conf.HasTestConfig() {
		if err = checkClearDataDir(conf.DataDir); err != nil {
			return err
		}
	}

	if err = checkWrites(conf.DataDir); err != nil {
		return err
	}

	network, err := eth2util.ForkVersionToNetwork(def.ForkVersion)
	if err != nil {
		return err
	}

	if network == eth2util.Mainnet.Name && conf.HasTestConfig() {
		return errors.New("cannot use test flags on mainnet")
	}

	peers, err := def.Peers()
	if err != nil {
		return err
	}

	defHash := fmt.Sprintf("%#x", def.DefinitionHash)

	key := conf.TestConfig.P2PKey
	if key == nil {
		var err error
		key, err = p2p.LoadPrivKey(conf.DataDir)
		if err != nil {
			return err
		}
	}

	pID, err := p2p.PeerIDFromKey(key.PubKey())
	if err != nil {
		return err
	}

	log.Info(ctx, "Starting local P2P networking peer")

	logPeerSummary(ctx, pID, peers, def.Operators)

	tcpNode, shutdown, err := setupP2P(ctx, key, conf, peers, def.DefinitionHash)
	if err != nil {
		return err
	}
	defer shutdown()

	nodeIdx, err := def.NodeIdx(tcpNode.ID())
	if err != nil {
		return errors.Wrap(err, "private key not matching definition file")
	}

	peerIds, err := def.PeerIDs()
	if err != nil {
		return errors.Wrap(err, "get peer IDs")
	}

	ex := newExchanger(tcpNode, nodeIdx.PeerIdx, peerIds, def.NumValidators, []sigType{
		sigLock,
		sigDepositData,
		sigValidatorRegistration,
	})

	// Register Frost libp2p handlers
	peerMap := make(map[peer.ID]cluster.NodeIdx)
	for _, p := range peers {
		nodeIdx, err := def.NodeIdx(p.ID)
		if err != nil {
			return err
		}
		peerMap[p.ID] = nodeIdx
	}

	caster := bcast.New(tcpNode, peerIds, key)

	// register bcast callbacks for frostp2p
	tp, err := newFrostP2P(tcpNode, peerMap, caster, def.Threshold, def.NumValidators)
	if err != nil {
		return errors.Wrap(err, "frost error")
	}

	// register bcast callbacks for lock hash k1 signature handler
	nodeSigCaster := newNodeSigBcast(peers, nodeIdx, caster)

	log.Info(ctx, "Waiting to connect to all peers...")

	// Improve UX of "context cancelled" errors when sync fails.
	ctx = errors.WithCtxErr(ctx, "p2p connection failed, please retry DKG")

	nextStepSync, stopSync, err := startSyncProtocol(ctx, tcpNode, key, def.DefinitionHash, peerIds, cancel, conf.TestConfig)
	if err != nil {
		return err
	}

	log.Info(ctx, "All peers connected, starting DKG ceremony")

	var shares []share
	switch def.DKGAlgorithm {
	case "default", "frost":
		shares, err = runFrostParallel(ctx, tp, uint32(def.NumValidators), uint32(len(peerMap)),
			uint32(def.Threshold), uint32(nodeIdx.ShareIdx), defHash)
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported dkg algorithm")
	}

	// DKG was step 1, advance to step 2
	if err := nextStepSync(ctx); err != nil {
		return err
	}

	// Sign, exchange and aggregate Deposit Data
	depositDatas, err := signAndAggDepositData(ctx, ex, shares, def.WithdrawalAddresses(), network, nodeIdx)
	if err != nil {
		return err
	}

	log.Debug(ctx, "Aggregated deposit data signatures")
	// Deposit data was step 2, advance to step 3
	if err := nextStepSync(ctx); err != nil {
		return err
	}

	// Sign, exchange and aggregate builder validator registration signatures.
	valRegs, err := signAndAggValidatorRegistrations(
		ctx,
		ex,
		shares,
		def.FeeRecipientAddresses(),
		registration.DefaultGasLimit,
		nodeIdx,
		def.ForkVersion,
	)
	if err != nil {
		return errors.Wrap(err, "builder validator registrations pre-generation")
	}

	log.Debug(ctx, "Aggregated builder validator registration signatures")
	// Pre-regs was step 3, advance to step 4
	if err := nextStepSync(ctx); err != nil {
		return err
	}

	// Sign, exchange and aggregate Lock Hash signatures
	lock, err := signAndAggLockHash(ctx, shares, def, nodeIdx, ex, depositDatas, valRegs)
	if err != nil {
		return err
	}

	log.Debug(ctx, "Aggregated lock hash signatures")
	// Lock hash aggregate was step 4, advance to step 5
	if err := nextStepSync(ctx); err != nil {
		return err
	}

	// Sign, exchange K1 signatures over Lock Hash
	lock.NodeSignatures, err = nodeSigCaster.exchange(ctx, key, lock.LockHash)
	if err != nil {
		return errors.Wrap(err, "k1 lock hash signature exchange")
	}

	if !cluster.SupportNodeSignatures(lock.Version) {
		lock.NodeSignatures = nil
	}

	log.Debug(ctx, "Exchanged node signatures")
	// Node signatures was step 5, advance to step 6
	if err := nextStepSync(ctx); err != nil {
		return err
	}

	if !conf.NoVerify {
		if err := lock.VerifySignatures(); err != nil {
			return errors.Wrap(err, "invalid lock file")
		}
	}

	// Write keystores, deposit data and cluster lock files after exchange of partial signatures in order
	// to prevent partial data writes in case of peer connection lost

	if conf.KeymanagerAddr != "" { // Save to keymanager
		if err = writeKeysToKeymanager(ctx, conf.KeymanagerAddr, conf.KeymanagerAuthToken, shares); err != nil {
			return err
		}
		log.Debug(ctx, "Imported keyshares to keymanager", z.Str("keymanager_address", conf.KeymanagerAddr))
	} else { // Else save to disk
		if err = writeKeysToDisk(conf, shares); err != nil {
			return err
		}
		log.Debug(ctx, "Saved keyshares to disk")
	}

	// dashboardURL is the Launchpad dashboard url for a given lock file.
	// If empty, either conf.Publish wasn't specified or there was a processing error in publishing
	// the generated lock file.
	var dashboardURL string

	if conf.Publish {
		if dashboardURL, err = writeLockToAPI(ctx, conf.PublishAddr, lock); err != nil {
			log.Warn(ctx, "Couldn't publish lock file to Obol API", err)
		}
	}

	if err = writeLock(conf.DataDir, lock); err != nil {
		return err
	}
	log.Debug(ctx, "Saved lock file to disk")

	if err := writeDepositData(depositDatas, network, conf.DataDir); err != nil {
		return err
	}
	log.Debug(ctx, "Saved deposit data file to disk")

	// Signature verification and disk key write was step 6, advance to step 7
	if err := nextStepSync(ctx); err != nil {
		return err
	}

	if err = stopSync(ctx); err != nil {
		return errors.Wrap(err, "sync shutdown") // Consider increasing --shutdown-delay if this occurs often.
	}

	if conf.TestConfig.ShutdownCallback != nil {
		conf.TestConfig.ShutdownCallback()
	}
	log.Debug(ctx, "Graceful shutdown delay", z.Int("seconds", int(conf.ShutdownDelay.Seconds())))
	time.Sleep(conf.ShutdownDelay)

	log.Info(ctx, "Successfully completed DKG ceremony 🎉")

	if dashboardURL != "" {
		log.Info(ctx, fmt.Sprintf("You can find your newly-created cluster dashboard here: %s", dashboardURL))
	}

	return nil
}

// setupP2P returns a started libp2p tcp node and a shutdown function.
func setupP2P(ctx context.Context, key *k1.PrivateKey, conf Config, peers []p2p.Peer, defHash []byte) (host.Host, func(), error) {
	var peerIDs []peer.ID
	for _, p := range peers {
		peerIDs = append(peerIDs, p.ID)
	}

	if err := p2p.VerifyP2PKey(peers, key); err != nil {
		return nil, nil, err
	}

	relays, err := p2p.NewRelays(ctx, conf.P2P.Relays, hex.EncodeToString(defHash))
	if err != nil {
		return nil, nil, err
	}

	connGater, err := p2p.NewConnGater(peerIDs, relays)
	if err != nil {
		return nil, nil, err
	}

	tcpNode, err := p2p.NewTCPNode(ctx, conf.P2P, key, connGater, false)
	if err != nil {
		return nil, nil, err
	}

	if conf.TestConfig.TCPNodeCallback != nil {
		conf.TestConfig.TCPNodeCallback(tcpNode)
	}

	p2p.RegisterConnectionLogger(ctx, tcpNode, peerIDs)

	for _, relay := range relays {
		relay := relay
		go p2p.NewRelayReserver(tcpNode, relay)(ctx)
	}

	go p2p.NewRelayRouter(tcpNode, peerIDs, relays)(ctx)

	// Register peerinfo server handler for identification to relays (but do not run peerinfo client).
	gitHash, _ := version.GitCommit()
	_ = peerinfo.New(tcpNode, peerIDs, version.Version, defHash, gitHash, nil)

	return tcpNode, func() {
		_ = tcpNode.Close()
	}, nil
}

// startSyncProtocol sets up a sync protocol server and clients for each peer and returns a step sync and shutdown functions
// when all peers are connected.
func startSyncProtocol(ctx context.Context, tcpNode host.Host, key *k1.PrivateKey, defHash []byte,
	peerIDs []peer.ID, onFailure func(), testConfig TestConfig,
) (func(context.Context) error, func(context.Context) error, error) {
	// Sign definition hash with charon-enr-private-key
	// Note: libp2p signing does another hash of the defHash.

	hashSig, err := ((*libp2pcrypto.Secp256k1PrivateKey)(key)).Sign(defHash)
	if err != nil {
		return nil, nil, errors.Wrap(err, "sign definition hash")
	}

	// DKG compatibility is minor version dependent.
	minorVersion := version.Version.Minor()

	server := sync.NewServer(tcpNode, len(peerIDs)-1, defHash, minorVersion)
	server.Start(ctx)

	var clients []*sync.Client
	for _, pID := range peerIDs {
		if tcpNode.ID() == pID {
			continue
		}

		ctx := log.WithCtx(ctx, z.Str("peer", p2p.PeerName(pID)))

		client := sync.NewClient(tcpNode, pID, hashSig, minorVersion, testConfig.SyncOpts...)
		clients = append(clients, client)

		go func() {
			err := client.Run(ctx)
			if err != nil && !errors.Is(err, context.Canceled) { // Only log and fail if this peer errored.
				log.Error(ctx, "Sync failed to peer", err)
				onFailure()
			}
		}()
	}

	// Check if all clients are connected.
	for {
		// Return if there is a context error.
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}

		if err := server.Err(); err != nil {
			return nil, nil, errors.Wrap(err, "sync server error")
		}

		var connectedCount int
		for _, client := range clients {
			if client.IsConnected() {
				connectedCount++
			}
		}

		if testConfig.SyncCallback != nil {
			testConfig.SyncCallback(connectedCount, tcpNode.ID())
		}

		// Break if all clients are connected
		if len(clients) == connectedCount {
			break
		}

		// Sleep for 250ms to let clients connect with each other.
		// Must be at least two times greater than the sync messages period specified in client.go NewClient().
		time.Sleep(time.Millisecond * 250)
	}

	// Disable reconnecting clients to other peer's server once all clients are connected.
	for _, client := range clients {
		client.DisableReconnect()
	}

	err = server.AwaitAllConnected(ctx)
	if err != nil {
		return nil, nil, err
	}

	var step int
	stepSyncFunc := func(ctx context.Context) error {
		// Start next step ourselves by incrementing our step client side
		step++
		for _, client := range clients {
			client.SetStep(step)
		}

		log.Debug(ctx, "Waiting for peers to start next step", z.Int("step", step))

		if err := server.AwaitAllAtStep(ctx, step); err != nil {
			return errors.Wrap(err, "sync step", z.Int("step", step))
		}

		return nil
	}

	// All peer start on step 0, so advance to step 1.
	if err := stepSyncFunc(ctx); err != nil {
		return nil, nil, err
	}

	// Shutdown function stops all clients and server
	shutdownFunc := func(ctx context.Context) error {
		for _, client := range clients {
			err := client.Shutdown(ctx)
			if err != nil {
				return err
			}
		}

		return server.AwaitAllShutdown(ctx)
	}

	return stepSyncFunc, shutdownFunc, nil
}

// signAndAggLockHash returns cluster lock file with aggregated signature after signing, exchange and aggregation of partial signatures.
func signAndAggLockHash(ctx context.Context, shares []share, def cluster.Definition,
	nodeIdx cluster.NodeIdx, ex *exchanger, depositDatas []eth2p0.DepositData, valRegs []core.VersionedSignedValidatorRegistration,
) (cluster.Lock, error) {
	vals, err := createDistValidators(shares, depositDatas, valRegs)
	if err != nil {
		return cluster.Lock{}, err
	}

	if !cluster.SupportPregenRegistrations(def.Version) {
		for i := range vals {
			vals[i].BuilderRegistration = cluster.BuilderRegistration{}
		}
	}

	lock := cluster.Lock{
		Definition: def,
		Validators: vals,
	}
	lock, err = lock.SetLockHash()
	if err != nil {
		return cluster.Lock{}, err
	}

	lockHashSig, err := signLockHash(nodeIdx.ShareIdx, shares, lock.LockHash)
	if err != nil {
		return cluster.Lock{}, err
	}

	peerSigs, err := ex.exchange(ctx, sigLock, lockHashSig)
	if err != nil {
		return cluster.Lock{}, err
	}

	pubkeyToShares := make(map[core.PubKey]share)
	for _, sh := range shares {
		pk, err := core.PubKeyFromBytes(sh.PubKey[:])
		if err != nil {
			return cluster.Lock{}, err
		}

		pubkeyToShares[pk] = sh
	}

	aggSigLockHash, aggPkLockHash, err := aggLockHashSig(peerSigs, pubkeyToShares, lock.LockHash)
	if err != nil {
		return cluster.Lock{}, err
	}

	err = tbls.VerifyAggregate(aggPkLockHash, aggSigLockHash, lock.LockHash)
	if err != nil {
		return cluster.Lock{}, errors.Wrap(err, "verify multisignature")
	}

	lock.SignatureAggregate = aggSigLockHash[:]

	return lock, nil
}

// signAndAggDepositData returns the deposit datas for each DV after signing, exchange and aggregation of partial signatures.
func signAndAggDepositData(ctx context.Context, ex *exchanger, shares []share, withdrawalAddresses []string,
	network string, nodeIdx cluster.NodeIdx,
) ([]eth2p0.DepositData, error) {
	parSig, despositMsgs, err := signDepositMsgs(shares, nodeIdx.ShareIdx, withdrawalAddresses, network)
	if err != nil {
		return nil, err
	}

	peerSigs, err := ex.exchange(ctx, sigDepositData, parSig)
	if err != nil {
		return nil, err
	}

	return aggDepositData(peerSigs, shares, despositMsgs, network)
}

// signAndAggValidatorRegistrations returns the pre-generated validator registrations objects after signing, exchange and aggregation of partial signatures.
func signAndAggValidatorRegistrations(
	ctx context.Context,
	ex *exchanger,
	shares []share,
	feeRecipients []string,
	gasLimit uint64,
	nodeIdx cluster.NodeIdx,
	forkVersion []byte,
) ([]core.VersionedSignedValidatorRegistration, error) {
	parSig, valRegs, err := signValidatorRegistrations(shares, nodeIdx.ShareIdx, feeRecipients, gasLimit, forkVersion)
	if err != nil {
		return nil, err
	}

	peerSigs, err := ex.exchange(ctx, sigValidatorRegistration, parSig)
	if err != nil {
		return nil, err
	}

	return aggValidatorRegistrations(peerSigs, shares, valRegs, forkVersion)
}

// aggLockHashSig returns the aggregated multi signature of the lock hash
// signed by all the private key shares of all the distributed validators.
func aggLockHashSig(data map[core.PubKey][]core.ParSignedData, shares map[core.PubKey]share, hash []byte) (tbls.Signature, []tbls.PublicKey, error) {
	var (
		sigs    []tbls.Signature
		pubkeys []tbls.PublicKey
	)

	for pk, psigs := range data {
		pk := pk
		psigs := psigs
		for _, s := range psigs {
			sig, err := tblsconv.SignatureFromBytes(s.Signature())
			if err != nil {
				return tbls.Signature{}, nil, errors.Wrap(err, "signature from bytes")
			}

			sh, ok := shares[pk]
			if !ok {
				// peerIdx is 0-indexed while shareIdx is 1-indexed
				return tbls.Signature{}, nil, errors.New("invalid pubkey in lock hash partial signature from peer",
					z.Int("peerIdx", s.ShareIdx-1), z.Str("pubkey", pk.String()))
			}

			pubshare, ok := sh.PublicShares[s.ShareIdx]
			if !ok {
				return tbls.Signature{}, nil, errors.New("invalid pubshare")
			}

			err = tbls.Verify(pubshare, hash, sig)
			if err != nil {
				return tbls.Signature{}, nil, errors.Wrap(err, "invalid lock hash partial signature from peer",
					z.Int("peerIdx", s.ShareIdx-1), z.Str("pubkey", pk.String()))
			}

			sigs = append(sigs, sig)
			pubkeys = append(pubkeys, pubshare)
		}
	}

	// Full BLS Signature Aggregation
	aggSig, err := tbls.Aggregate(sigs)
	if err != nil {
		return tbls.Signature{}, nil, errors.Wrap(err, "bls aggregate Signatures")
	}

	return aggSig, pubkeys, nil
}

// signLockHash returns a partially signed dataset containing signatures of the lock hash.
func signLockHash(shareIdx int, shares []share, hash []byte) (core.ParSignedDataSet, error) {
	set := make(core.ParSignedDataSet)
	for _, share := range shares {
		pk, err := core.PubKeyFromBytes(share.PubKey[:])
		if err != nil {
			return nil, err
		}

		sig, err := tbls.Sign(share.SecretShare, hash)
		if err != nil {
			return nil, err
		}

		set[pk] = core.NewPartialSignature(tblsconv.SigToCore(sig), shareIdx)
	}

	return set, nil
}

// signDepositMsgs returns a partially signed dataset containing signatures of the deposit message signing root.
func signDepositMsgs(shares []share, shareIdx int, withdrawalAddresses []string, network string) (core.ParSignedDataSet, map[core.PubKey]eth2p0.DepositMessage, error) {
	msgs := make(map[core.PubKey]eth2p0.DepositMessage)
	set := make(core.ParSignedDataSet)
	for i, share := range shares {
		withdrawalHex, err := eth2util.ChecksumAddress(withdrawalAddresses[i])
		if err != nil {
			return nil, nil, err
		}
		pubkey, err := tblsconv.PubkeyToETH2(share.PubKey)
		if err != nil {
			return nil, nil, err
		}

		pk, err := core.PubKeyFromBytes(share.PubKey[:])
		if err != nil {
			return nil, nil, err
		}

		msg, err := deposit.NewMessage(pubkey, withdrawalHex, deposit.MaxValidatorAmount)
		if err != nil {
			return nil, nil, err
		}

		sigRoot, err := deposit.GetMessageSigningRoot(msg, network)
		if err != nil {
			return nil, nil, err
		}

		sig, err := tbls.Sign(share.SecretShare, sigRoot[:])
		if err != nil {
			return nil, nil, err
		}

		set[pk] = core.NewPartialSignature(tblsconv.SigToCore(sig), shareIdx)
		msgs[pk] = eth2p0.DepositMessage{
			PublicKey:             msg.PublicKey,
			WithdrawalCredentials: msg.WithdrawalCredentials,
			Amount:                msg.Amount,
		}
	}

	return set, msgs, nil
}

// signValidatorRegistrations returns a partially signed dataset containing signatures of the validator registrations signing root.
func signValidatorRegistrations(shares []share, shareIdx int, feeRecipients []string, gasLimit uint64, forkVersion []byte) (core.ParSignedDataSet, map[core.PubKey]core.VersionedSignedValidatorRegistration, error) {
	msgs := make(map[core.PubKey]core.VersionedSignedValidatorRegistration)
	set := make(core.ParSignedDataSet)
	for idx, share := range shares {
		pubkey, err := tblsconv.PubkeyToETH2(share.PubKey)
		if err != nil {
			return nil, nil, err
		}

		timestamp, err := eth2util.ForkVersionToGenesisTime(forkVersion)
		if err != nil {
			return nil, nil, err
		}

		regMsg, err := registration.NewMessage(pubkey, feeRecipients[idx], gasLimit, timestamp)
		if err != nil {
			return nil, nil, err
		}

		sigRoot, err := registration.GetMessageSigningRoot(regMsg, eth2p0.Version(forkVersion))
		if err != nil {
			return nil, nil, err
		}

		sig, err := tbls.Sign(share.SecretShare, sigRoot[:])
		if err != nil {
			return nil, nil, err
		}

		signedReg, err := core.NewVersionedSignedValidatorRegistration(&eth2api.VersionedSignedValidatorRegistration{
			Version: eth2spec.BuilderVersionV1,
			V1: &eth2v1.SignedValidatorRegistration{
				Message:   regMsg,
				Signature: tblsconv.SigToETH2(sig),
			},
		})
		if err != nil {
			return nil, nil, err
		}

		corePubkey := core.PubKeyFrom48Bytes(pubkey)

		set[corePubkey] = core.NewPartialSignature(tblsconv.SigToCore(sig), shareIdx)
		msgs[corePubkey] = signedReg
	}

	return set, msgs, nil
}

// aggDepositData returns the threshold aggregated deposit datas per DV.
func aggDepositData(data map[core.PubKey][]core.ParSignedData, shares []share,
	msgs map[core.PubKey]eth2p0.DepositMessage, network string,
) ([]eth2p0.DepositData, error) {
	pubkeyToPubShares := make(map[core.PubKey]map[int]tbls.PublicKey)
	for _, sh := range shares {
		pk, err := core.PubKeyFromBytes(sh.PubKey[:])
		if err != nil {
			return nil, err
		}

		pubkeyToPubShares[pk] = sh.PublicShares
	}

	var resp []eth2p0.DepositData

	for pk, psigsData := range data {
		pk := pk
		psigsData := psigsData

		msg, ok := msgs[pk]
		if !ok {
			return nil, errors.New("deposit message not found")
		}
		sigRoot, err := deposit.GetMessageSigningRoot(msg, network)
		if err != nil {
			return nil, err
		}

		psigs := make(map[int]tbls.Signature)
		for _, s := range psigsData {
			sig, err := tblsconv.SignatureFromBytes(s.Signature())
			if err != nil {
				return nil, errors.Wrap(err, "signature from core")
			}

			pubshares, ok := pubkeyToPubShares[pk]
			if !ok {
				return nil, errors.New("invalid pubkey in deposit data partial signature from peer",
					z.Int("peerIdx", s.ShareIdx-1), // peerIdx is 0-indexed while shareIdx is 1-indexed
					z.Str("pubkey", pk.String()))
			}

			pubshare, ok := pubshares[s.ShareIdx]
			if !ok {
				return nil, errors.New("invalid pubshare")
			}

			err = tbls.Verify(pubshare, sigRoot[:], sig)
			if err != nil {
				return nil, errors.New("invalid deposit data partial signature from peer",
					z.Int("peerIdx", s.ShareIdx-1), z.Str("pubkey", pk.String()))
			}

			psigs[s.ShareIdx] = sig
		}

		// Aggregate signatures per DV
		asig, err := tbls.ThresholdAggregate(psigs)
		if err != nil {
			return nil, err
		}

		pubkey, err := tblsconv.PubkeyFromCore(pk)
		if err != nil {
			return nil, err
		}

		err = tbls.Verify(pubkey, sigRoot[:], asig)
		if err != nil {
			return nil, errors.Wrap(err, "invalid deposit data aggregated signature")
		}

		resp = append(resp, eth2p0.DepositData{
			PublicKey:             msg.PublicKey,
			WithdrawalCredentials: msg.WithdrawalCredentials,
			Amount:                msg.Amount,
			Signature:             tblsconv.SigToETH2(asig),
		})
	}

	return resp, nil
}

// aggValidatorRegistrations returns the threshold aggregated validator registrations per DV.
func aggValidatorRegistrations(
	data map[core.PubKey][]core.ParSignedData,
	shares []share,
	msgs map[core.PubKey]core.VersionedSignedValidatorRegistration,
	forkVersion []byte,
) ([]core.VersionedSignedValidatorRegistration, error) {
	pubkeyToPubShares := make(map[core.PubKey]map[int]tbls.PublicKey)
	for _, sh := range shares {
		pk, err := core.PubKeyFromBytes(sh.PubKey[:])
		if err != nil {
			return nil, err
		}

		pubkeyToPubShares[pk] = sh.PublicShares
	}

	var resp []core.VersionedSignedValidatorRegistration

	for pk, psigsData := range data {
		pk := pk
		psigsData := psigsData

		msg, ok := msgs[pk]
		if !ok {
			return nil, errors.New("validator registration not found")
		}
		sigRoot, err := registration.GetMessageSigningRoot(msg.V1.Message, eth2p0.Version(forkVersion))
		if err != nil {
			return nil, err
		}

		psigs := make(map[int]tbls.Signature)
		for _, s := range psigsData {
			sig, err := tblsconv.SignatureFromBytes(s.Signature())
			if err != nil {
				return nil, errors.Wrap(err, "signature from core")
			}

			pubshares, ok := pubkeyToPubShares[pk]
			if !ok {
				return nil, errors.New("invalid pubkey in validator registrations partial signature from peer",
					z.Int("peerIdx", s.ShareIdx-1), // peerIdx is 0-indexed while shareIdx is 1-indexed
					z.Str("pubkey", pk.String()))
			}

			pubshare, ok := pubshares[s.ShareIdx]
			if !ok {
				return nil, errors.New("invalid pubshare")
			}

			err = tbls.Verify(pubshare, sigRoot[:], sig)
			if err != nil {
				return nil, errors.New("invalid validator registration partial signature from peer",
					z.Int("peerIdx", s.ShareIdx-1), z.Str("pubkey", pk.String()))
			}

			psigs[s.ShareIdx] = sig
		}

		// Aggregate signatures per DV
		asig, err := tbls.ThresholdAggregate(psigs)
		if err != nil {
			return nil, err
		}

		pubkey, err := tblsconv.PubkeyFromCore(pk)
		if err != nil {
			return nil, err
		}

		err = tbls.Verify(pubkey, sigRoot[:], asig)
		if err != nil {
			return nil, errors.Wrap(err, "invalid validator registration aggregated signature")
		}

		signedReg, err := setRegistrationSignature(msg, asig[:])
		if err != nil {
			return nil, errors.Wrap(err, "set signature")
		}

		resp = append(resp, signedReg)
	}

	return resp, nil
}

// createDistValidators returns a slice of distributed validators from the provided
// shares and deposit datas.
func createDistValidators(shares []share, depositDatas []eth2p0.DepositData, valRegs []core.VersionedSignedValidatorRegistration) ([]cluster.DistValidator, error) {
	var dvs []cluster.DistValidator
	for _, s := range shares {
		msg := msgFromShare(s)

		ddIdx := -1
		for i, dd := range depositDatas {
			if !bytes.Equal(msg.PubKey, dd.PublicKey[:]) {
				continue
			}
			ddIdx = i

			break
		}
		if ddIdx == -1 {
			return nil, errors.New("deposit data not found")
		}

		regIdx := -1
		for i, reg := range valRegs {
			pubkey, err := reg.PubKey()
			if err != nil {
				return nil, err
			}

			if !bytes.Equal(msg.PubKey, pubkey[:]) {
				continue
			}

			regIdx = i

			break
		}
		if regIdx == -1 {
			return nil, errors.New("validator registration not found")
		}

		reg, err := builderRegistrationFromETH2(valRegs[regIdx])
		if err != nil {
			return nil, err
		}

		dvs = append(dvs, cluster.DistValidator{
			PubKey:    msg.PubKey,
			PubShares: msg.PubShares,
			PartialDepositData: []cluster.DepositData{
				{
					PubKey:                depositDatas[ddIdx].PublicKey[:],
					WithdrawalCredentials: depositDatas[ddIdx].WithdrawalCredentials,
					Amount:                int(depositDatas[ddIdx].Amount),
					Signature:             depositDatas[ddIdx].Signature[:],
				},
			},
			BuilderRegistration: reg,
		})
	}

	return dvs, nil
}

// writeLockToAPI posts the lock file to obol-api and returns the Launchpad dashboard URL.
func writeLockToAPI(ctx context.Context, publishAddr string, lock cluster.Lock) (string, error) {
	cl, err := obolapi.New(publishAddr)
	if err != nil {
		return "", err
	}

	if err := cl.PublishLock(ctx, lock); err != nil {
		return "", err
	}

	log.Debug(ctx, "Published lock file to api")

	return cl.LaunchpadURLForLock(lock), nil
}

// validateKeymanagerFlags returns an error if one keymanager flag is present but the other is not.
func validateKeymanagerFlags(ctx context.Context, addr, authToken string) error {
	if addr != "" && authToken == "" {
		return errors.New("--keymanager-address provided but --keymanager-auth-token absent. Please fix configuration flags")
	}
	if addr == "" && authToken != "" {
		return errors.New("--keymanager-auth-token provided but --keymanager-address absent. Please fix configuration flags")
	}

	keymanagerURL, err := url.Parse(addr)
	if err != nil {
		return errors.Wrap(err, "failed to parse keymanager addr", z.Str("addr", addr))
	}

	if keymanagerURL.Scheme != "https" {
		log.Warn(ctx, "Keymanager URL does not use https protocol", nil, z.Str("addr", addr))
	}

	return nil
}

// logPeerSummary logs peer summary with peer names and their ethereum addresses.
func logPeerSummary(ctx context.Context, currentPeer peer.ID, peers []p2p.Peer, operators []cluster.Operator) {
	for i, p := range peers {
		opts := []z.Field{z.Str("peer", p.Name), z.Int("index", p.Index)}
		if operators[i].Address != "" {
			opts = append(opts, z.Str("address", operators[i].Address))
		}
		if p.ID == currentPeer {
			opts = append(opts, z.Str("you", "⭐️"))
		}
		log.Info(ctx, "Peer summary", opts...)
	}
}

func builderRegistrationFromETH2(reg core.VersionedSignedValidatorRegistration) (cluster.BuilderRegistration, error) {
	feeRecipient, err := reg.FeeRecipient()
	if err != nil {
		return cluster.BuilderRegistration{}, errors.Wrap(err, "get fee recipient")
	}

	gasLimit, err := reg.GasLimit()
	if err != nil {
		return cluster.BuilderRegistration{}, errors.Wrap(err, "get gasLimit")
	}

	timestamp, err := reg.Timestamp()
	if err != nil {
		return cluster.BuilderRegistration{}, errors.Wrap(err, "get timestamp")
	}

	pubKey, err := reg.PubKey()
	if err != nil {
		return cluster.BuilderRegistration{}, errors.Wrap(err, "get pubKey")
	}

	return cluster.BuilderRegistration{
		Message: cluster.Registration{
			FeeRecipient: feeRecipient[:],
			GasLimit:     int(gasLimit),
			Timestamp:    timestamp,
			PubKey:       pubKey[:],
		},
		Signature: reg.Signature(),
	}, nil
}

func setRegistrationSignature(reg core.VersionedSignedValidatorRegistration, sig core.Signature) (core.VersionedSignedValidatorRegistration, error) {
	switch reg.Version {
	case eth2spec.BuilderVersionV1:
		reg.V1.Signature = sig.ToETH2()
	default:
		return core.VersionedSignedValidatorRegistration{}, errors.New("unknown type")
	}

	return reg, nil
}
