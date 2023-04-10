// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/app/peerinfo"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/dkg/sync"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/eth2util/keymanager"
	"github.com/obolnetwork/charon/p2p"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
	tblsconv2 "github.com/obolnetwork/charon/tbls/v2/tblsconv"
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

	TestDef              *cluster.Definition
	TestSyncCallback     func(connected int, id peer.ID)
	TestStoreKeysFunc    func(secrets []tblsv2.PrivateKey, dir string) error
	TestTCPNodeCallback  func(host.Host)
	TestShutdownCallback func()
}

// HasTestConfig returns true if any of the test config fields are set.
func (c Config) HasTestConfig() bool {
	return c.TestStoreKeysFunc != nil || c.TestSyncCallback != nil || c.TestDef != nil || c.TestTCPNodeCallback != nil
}

// Run executes a dkg ceremony and writes secret share keystore and cluster lock files as output to disk.
//
//nolint:maintidx // Refactor into smaller steps.
func Run(ctx context.Context, conf Config) (err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ctx = log.WithTopic(ctx, "dkg")
	defer func() {
		if err != nil {
			log.Error(ctx, "Fatal error", err)
		}
	}()

	version.LogInfo(ctx, "Charon DKG starting")

	def, err := loadDefinition(ctx, conf)
	if err != nil {
		return err
	}

	if err := validateKeymanagerFlags(conf.KeymanagerAddr, conf.KeymanagerAuthToken); err != nil {
		return err
	}

	// Check if keymanager address is reachable.
	if conf.KeymanagerAddr != "" {
		cl := keymanager.New(conf.KeymanagerAddr, conf.KeymanagerAuthToken)
		if err = cl.VerifyConnection(ctx); err != nil {
			return errors.Wrap(err, "verify keymanager address")
		}
	}

	if err = checkClearDataDir(conf.DataDir); err != nil {
		return err
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

	key, err := p2p.LoadPrivKey(conf.DataDir)
	if err != nil {
		return err
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

	ex := newExchanger(tcpNode, nodeIdx.PeerIdx, peerIds, def.NumValidators)

	// Register Frost libp2p handlers
	peerMap := make(map[peer.ID]cluster.NodeIdx)
	for _, p := range peers {
		nodeIdx, err := def.NodeIdx(p.ID)
		if err != nil {
			return err
		}
		peerMap[p.ID] = nodeIdx
	}
	tp := newFrostP2P(tcpNode, peerMap, key, def.Threshold)

	log.Info(ctx, "Waiting to connect to all peers...")

	// Improve UX of "context cancelled" errors when sync fails.
	ctx = errors.WithCtxErr(ctx, "p2p connection failed, please retry DKG")

	stopSync, err := startSyncProtocol(ctx, tcpNode, key, def.DefinitionHash, peerIds, cancel, conf.TestSyncCallback)
	if err != nil {
		return err
	}

	log.Info(ctx, "All peers connected, starting DKG ceremony")

	var shares []share
	switch def.DKGAlgorithm {
	case "keycast":
		tp := keycastP2P{
			tcpNode:   tcpNode,
			peers:     peers,
			clusterID: defHash,
		}

		shares, err = runKeyCast(ctx, def, tp, nodeIdx.PeerIdx)
		if err != nil {
			return err
		}
	case "default", "frost":
		shares, err = runFrostParallel(ctx, tp, uint32(def.NumValidators), uint32(len(peerMap)),
			uint32(def.Threshold), uint32(nodeIdx.ShareIdx), defHash)
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported dkg algorithm")
	}

	// Sign, exchange and aggregate Deposit Data
	depositDatas, err := signAndAggDepositData(ctx, ex, shares, def.WithdrawalAddresses(), network, nodeIdx)
	if err != nil {
		return err
	}

	log.Debug(ctx, "Aggregated deposit data signatures")

	// Sign, exchange and aggregate Lock Hash signatures
	lock, err := signAndAggLockHash(ctx, shares, def, nodeIdx, ex, depositDatas)
	if err != nil {
		return err
	}
	if !conf.NoVerify {
		if err := lock.VerifySignatures(); err != nil {
			return errors.Wrap(err, "invalid lock file")
		}
	}
	log.Debug(ctx, "Aggregated lock hash signatures")

	if err = stopSync(ctx); err != nil {
		return errors.Wrap(err, "sync shutdown") // Consider increasing --shutdown-delay if this occurs often.
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

	if conf.Publish {
		if err = writeLockToAPI(ctx, conf.PublishAddr, lock); err != nil {
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

	// TODO(corver): Improve graceful shutdown, see https://github.com/ObolNetwork/charon/issues/887
	if conf.TestShutdownCallback != nil {
		conf.TestShutdownCallback()
	}
	log.Debug(ctx, "Graceful shutdown delay", z.Int("seconds", int(conf.ShutdownDelay.Seconds())))
	time.Sleep(conf.ShutdownDelay)

	log.Info(ctx, "Successfully completed DKG ceremony 🎉")

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

	if conf.TestTCPNodeCallback != nil {
		conf.TestTCPNodeCallback(tcpNode)
	}

	p2p.RegisterConnectionLogger(ctx, tcpNode, peerIDs)

	for _, relay := range relays {
		relay := relay
		go p2p.NewRelayReserver(tcpNode, relay)(ctx)
	}

	go p2p.NewRelayRouter(tcpNode, peerIDs, relays)(ctx)

	// Register peerinfo server handler for identification to relays (but do not run peerinfo client).
	gitHash, _ := version.GitCommit(ctx)
	_ = peerinfo.New(tcpNode, peerIDs, version.Version, defHash, gitHash, nil)

	return tcpNode, func() {
		_ = tcpNode.Close()
	}, nil
}

// startSyncProtocol sets up a sync protocol server and clients for each peer and returns a shutdown function
// when all peers are connected.
func startSyncProtocol(ctx context.Context, tcpNode host.Host, key *k1.PrivateKey, defHash []byte,
	peerIDs []peer.ID, onFailure func(), testCallback func(connected int, id peer.ID),
) (func(context.Context) error, error) {
	// Sign definition hash with charon-enr-private-key
	// Note: libp2p signing does another hash of the defHash.

	hashSig, err := ((*libp2pcrypto.Secp256k1PrivateKey)(key)).Sign(defHash)
	if err != nil {
		return nil, errors.Wrap(err, "sign definition hash")
	}

	// DKG compatibility is minor version dependent.
	minorVersion, err := version.Minor(version.Version)
	if err != nil {
		return nil, errors.Wrap(err, "get version")
	}

	server := sync.NewServer(tcpNode, len(peerIDs)-1, defHash, minorVersion)
	server.Start(ctx)

	var clients []*sync.Client
	for _, pID := range peerIDs {
		if tcpNode.ID() == pID {
			continue
		}

		ctx := log.WithCtx(ctx, z.Str("peer", p2p.PeerName(pID)))
		client := sync.NewClient(tcpNode, pID, hashSig, minorVersion)
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
			return nil, ctx.Err()
		}

		if err := server.Err(); err != nil {
			return nil, errors.Wrap(err, "sync server error")
		}

		var connectedCount int
		for _, client := range clients {
			if client.IsConnected() {
				connectedCount++
			}
		}

		if testCallback != nil {
			testCallback(connectedCount, tcpNode.ID())
		}

		// Break if all clients are connected
		if len(clients) == connectedCount {
			break
		}

		// Sleep for 100ms to let clients connect with each other.
		time.Sleep(time.Millisecond * 100)
	}

	// Disable reconnecting clients to other peer's server once all clients are connected.
	for _, client := range clients {
		client.DisableReconnect()
	}

	err = server.AwaitAllConnected(ctx)
	if err != nil {
		return nil, err
	}

	// Shutdown function stops all clients and server
	return func(ctx context.Context) error {
		for _, client := range clients {
			err := client.Shutdown(ctx)
			if err != nil {
				return err
			}
		}

		return server.AwaitAllShutdown(ctx)
	}, nil
}

// signAndAggLockHash returns cluster lock file with aggregated signature after signing, exchange and aggregation of partial signatures.
func signAndAggLockHash(ctx context.Context, shares []share, def cluster.Definition,
	nodeIdx cluster.NodeIdx, ex *exchanger, depositDatas []eth2p0.DepositData,
) (cluster.Lock, error) {
	vals, err := createDistValidators(shares, depositDatas)
	if err != nil {
		return cluster.Lock{}, err
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

	err = tblsv2.VerifyAggregate(aggPkLockHash, aggSigLockHash, lock.LockHash)
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

// aggLockHashSig returns the aggregated multi signature of the lock hash
// signed by all the private key shares of all the distributed validators.
func aggLockHashSig(data map[core.PubKey][]core.ParSignedData, shares map[core.PubKey]share, hash []byte) (tblsv2.Signature, []tblsv2.PublicKey, error) {
	var (
		sigs    []tblsv2.Signature
		pubkeys []tblsv2.PublicKey
	)

	for pk, psigs := range data {
		pk := pk
		psigs := psigs
		for _, s := range psigs {
			sig, err := tblsconv2.SignatureFromBytes(s.Signature())
			if err != nil {
				return tblsv2.Signature{}, nil, errors.Wrap(err, "signature from bytes")
			}

			sh, ok := shares[pk]
			if !ok {
				// peerIdx is 0-indexed while shareIdx is 1-indexed
				return tblsv2.Signature{}, nil, errors.New("invalid pubkey in lock hash partial signature from peer",
					z.Int("peerIdx", s.ShareIdx-1), z.Str("pubkey", pk.String()))
			}

			pubshare, ok := sh.PublicShares[s.ShareIdx]
			if !ok {
				return tblsv2.Signature{}, nil, errors.New("invalid pubshare")
			}

			err = tblsv2.Verify(pubshare, hash, sig)
			if err != nil {
				return tblsv2.Signature{}, nil, errors.Wrap(err, "invalid lock hash partial signature from peer",
					z.Int("peerIdx", s.ShareIdx-1), z.Str("pubkey", pk.String()))
			}

			sigs = append(sigs, sig)
			pubkeys = append(pubkeys, pubshare)
		}
	}

	// Full BLS Signature Aggregation
	aggSig, err := tblsv2.Aggregate(sigs)
	if err != nil {
		return tblsv2.Signature{}, nil, errors.Wrap(err, "bls aggregate Signatures")
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

		sig, err := tblsv2.Sign(share.SecretShare, hash)
		if err != nil {
			return nil, err
		}

		set[pk] = core.NewPartialSignature(tblsconv2.SigToCore(sig), shareIdx)
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
		pubkey, err := tblsconv2.PubkeyToETH2(share.PubKey)
		if err != nil {
			return nil, nil, err
		}

		pk, err := core.PubKeyFromBytes(share.PubKey[:])
		if err != nil {
			return nil, nil, err
		}

		msg, err := deposit.NewMessage(pubkey, withdrawalHex)
		if err != nil {
			return nil, nil, err
		}

		sigRoot, err := deposit.GetMessageSigningRoot(msg, network)
		if err != nil {
			return nil, nil, err
		}

		sig, err := tblsv2.Sign(share.SecretShare, sigRoot[:])
		if err != nil {
			return nil, nil, err
		}

		set[pk] = core.NewPartialSignature(tblsconv2.SigToCore(sig), shareIdx)
		msgs[pk] = eth2p0.DepositMessage{
			PublicKey:             msg.PublicKey,
			WithdrawalCredentials: msg.WithdrawalCredentials,
			Amount:                msg.Amount,
		}
	}

	return set, msgs, nil
}

// aggDepositData returns the threshold aggregated deposit datas per DV.
func aggDepositData(data map[core.PubKey][]core.ParSignedData, shares []share,
	msgs map[core.PubKey]eth2p0.DepositMessage, network string,
) ([]eth2p0.DepositData, error) {
	pubkeyToPubShares := make(map[core.PubKey]map[int]tblsv2.PublicKey)
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

		psigs := make(map[int]tblsv2.Signature)
		for _, s := range psigsData {
			sig, err := tblsconv2.SignatureFromBytes(s.Signature())
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

			err = tblsv2.Verify(pubshare, sigRoot[:], sig)
			if err != nil {
				return nil, errors.New("invalid deposit data partial signature from peer",
					z.Int("peerIdx", s.ShareIdx-1), z.Str("pubkey", pk.String()))
			}

			psigs[s.ShareIdx] = sig
		}

		// Aggregate signatures per DV
		asig, err := tblsv2.ThresholdAggregate(psigs)
		if err != nil {
			return nil, err
		}

		pubkey, err := tblsconv2.PubkeyFromCore(pk)
		if err != nil {
			return nil, err
		}

		err = tblsv2.Verify(pubkey, sigRoot[:], asig)
		if err != nil {
			return nil, errors.Wrap(err, "invalid deposit data aggregated signature")
		}

		resp = append(resp, eth2p0.DepositData{
			PublicKey:             msg.PublicKey,
			WithdrawalCredentials: msg.WithdrawalCredentials,
			Amount:                msg.Amount,
			Signature:             tblsconv2.SigToETH2(asig),
		})
	}

	return resp, nil
}

// createDistValidators returns a slice of distributed validators from the provided
// shares and deposit datas.
func createDistValidators(shares []share, depositDatas []eth2p0.DepositData) ([]cluster.DistValidator, error) {
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

		dvs = append(dvs, cluster.DistValidator{
			PubKey:    msg.PubKey,
			PubShares: msg.PubShares,
			DepositData: cluster.DepositData{
				PubKey:                depositDatas[ddIdx].PublicKey[:],
				WithdrawalCredentials: depositDatas[ddIdx].WithdrawalCredentials,
				Amount:                int(depositDatas[ddIdx].Amount),
				Signature:             depositDatas[ddIdx].Signature[:],
			},
		})
	}

	return dvs, nil
}

// writeLockToAPI posts the lock file to obol-api.
func writeLockToAPI(ctx context.Context, publishAddr string, lock cluster.Lock) error {
	cl := obolapi.New(publishAddr)

	if err := cl.PublishLock(ctx, lock); err != nil {
		return err
	}

	log.Debug(ctx, "Published lock file to api")

	return nil
}

// validateKeymanagerFlags returns an error if one keymanager flag is present but the other is not.
func validateKeymanagerFlags(addr, authToken string) error {
	if addr != "" && authToken == "" {
		return errors.New("--keymanager-address provided but --keymanager-auth-token absent. Please fix configuration flags")
	}
	if addr == "" && authToken != "" {
		return errors.New("--keymanager-auth-token provided but --keymanager-address absent. Please fix configuration flags")
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
