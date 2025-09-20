// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth1wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/dkg/bcast"
	"github.com/obolnetwork/charon/dkg/pedersen"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
)

const (
	sigExchangeTimeout = 30 * time.Second
)

type ReshareDKGConfig struct {
	DataDir   string
	OutputDir string
	DKG       Config
}

type AddOperatorsDKGConfig struct {
	DataDir      string
	OutputDir    string
	NewENRs      []string
	NewThreshold int
	DKG          Config
}

func RunAddOperatorsDKG(ctx context.Context, conf *AddOperatorsDKGConfig, lock *cluster.Lock, shares []*pedersen.Share) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	eth1Cl := eth1wrap.NewDefaultEthClientRunner(conf.DKG.ExecutionEngineAddr)
	go eth1Cl.Run(ctx)

	peers, err := buildPeersList(lock, conf)
	if err != nil {
		return err
	}

	key, err := p2p.LoadPrivKey(conf.DataDir)
	if err != nil {
		return err
	}

	pID, err := p2p.PeerIDFromKey(key.PubKey())
	if err != nil {
		return err
	}

	log.Info(ctx, "Starting local P2P networking peer")
	logPeerSummary(ctx, pID, peers, nil)

	p2pNode, shutdown, err := setupP2P(ctx, key, conf.DKG, peers, lock.DefinitionHash)
	if err != nil {
		return err
	}
	defer shutdown()

	peerIDs, peerMap := buildPeerMap(peers)
	newPeerIDs := peerIDs[len(lock.Operators):]
	nodeIdx := peerMap[pID]

	ex := newExchanger(p2pNode, nodeIdx.PeerIdx, peerIDs, []sigType{sigLock}, sigExchangeTimeout)
	caster := bcast.New(p2pNode, peerIDs, key)
	nodeSigCaster := newNodeSigBcast(peers, nodeIdx, caster)

	// register pedersen protocol messages
	totalShares := len(lock.Validators)
	pedersenReshareConfig := pedersen.NewReshareConfig(totalShares, conf.NewThreshold, newPeerIDs)
	pedersenConfig := pedersen.NewConfig(p2pNode.ID(), peerMap, lock.Threshold, lock.DefinitionHash, pedersenReshareConfig)
	pedersenBoard := pedersen.NewBoard(ctx, p2pNode, pedersenConfig, caster)

	log.Info(ctx, "Waiting to connect to all peers...")

	nextStepSync, stopSync, err := startSyncProtocol(ctx, p2pNode, key, lock.DefinitionHash, peerIDs, cancel, TestConfig{})
	if err != nil {
		return err
	}

	newShares, err := pedersen.RunReshareDKG(ctx, pedersenConfig, pedersenBoard, shares)
	if err != nil {
		return err
	}

	if err := nextStepSync(ctx); err != nil {
		return errors.Wrap(err, "sync next step")
	}

	// Updating the lock.
	newDef := lock.Definition
	newDef.Threshold = conf.NewThreshold
	newDef.Creator = cluster.Creator{}

	enrs := make([]string, len(newDef.Operators)+len(conf.NewENRs))
	for i := range newDef.Operators {
		enrs[i] = newDef.Operators[i].ENR
	}

	for i, newENR := range conf.NewENRs {
		enrs[len(newDef.Operators)+i] = newENR
	}

	newDef.Operators = make([]cluster.Operator, len(enrs))
	for i, enr := range enrs {
		newDef.Operators[i] = cluster.Operator{
			ENR: enr,
		}
	}

	newDef, err = newDef.SetDefinitionHashes()
	if err != nil {
		return errors.Wrap(err, "set definition hashes")
	}

	newLock := cluster.Lock{
		Definition: newDef,
		Validators: lock.Validators,
	}

	cshares := copyToShares(newShares)
	for vi := range lock.Validators {
		msg := msgFromShare(cshares[vi])
		lock.Validators[vi].PubShares = msg.PubShares
	}

	newLock, err = newLock.SetLockHash()
	if err != nil {
		return errors.Wrap(err, "set lock hash")
	}

	lockHashSig, err := signLockHash(nodeIdx.ShareIdx, cshares, newLock.LockHash)
	if err != nil {
		return err
	}

	if err := nextStepSync(ctx); err != nil {
		return errors.Wrap(err, "sync next step")
	}

	peerSigs, err := ex.exchange(ctx, sigLock, lockHashSig)
	if err != nil {
		return err
	}

	pubkeyToShares := make(map[core.PubKey]share)
	for _, sh := range cshares {
		pk, err := core.PubKeyFromBytes(sh.PubKey[:])
		if err != nil {
			return err
		}

		pubkeyToShares[pk] = sh
	}

	aggSigLockHash, aggPkLockHash, err := aggLockHashSig(peerSigs, pubkeyToShares, newLock.LockHash)
	if err != nil {
		return err
	}

	if err := tbls.VerifyAggregate(aggPkLockHash, aggSigLockHash, newLock.LockHash); err != nil {
		return errors.Wrap(err, "verify multisignature")
	}

	newLock.SignatureAggregate = aggSigLockHash[:]

	newLock.NodeSignatures, err = nodeSigCaster.exchange(ctx, key, newLock.LockHash)
	if err != nil {
		return errors.Wrap(err, "k1 lock hash signature exchange")
	}

	if err := newLock.VerifySignatures(eth1Cl); err != nil {
		return errors.Wrap(err, "invalid lock file signatures")
	}

	if err := nextStepSync(ctx); err != nil {
		return errors.Wrap(err, "sync next step")
	}

	if err = storeKeys(newShares, conf.OutputDir); err != nil {
		return err
	}

	if err = writeLock(conf.OutputDir, newLock); err != nil {
		return err
	}

	if err = stopSync(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return errors.Wrap(err, "sync shutdown")
	}

	log.Debug(ctx, "Graceful shutdown delay", z.Int("seconds", int(conf.DKG.ShutdownDelay.Seconds())))
	time.Sleep(conf.DKG.ShutdownDelay)

	return nil
}

// RunReshareDKG runs a resharing DKG using the provided lock and existing shares.
func RunReshareDKG(ctx context.Context, conf *ReshareDKGConfig, lock *cluster.Lock, shares []*pedersen.Share) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	eth1Cl := eth1wrap.NewDefaultEthClientRunner(conf.DKG.ExecutionEngineAddr)
	go eth1Cl.Run(ctx)

	peers, err := lock.Peers()
	if err != nil {
		return err
	}

	key, err := p2p.LoadPrivKey(conf.DataDir)
	if err != nil {
		return err
	}

	pID, err := p2p.PeerIDFromKey(key.PubKey())
	if err != nil {
		return err
	}

	log.Info(ctx, "Starting local P2P networking peer")
	logPeerSummary(ctx, pID, peers, lock.Operators)

	p2pNode, shutdown, err := setupP2P(ctx, key, conf.DKG, peers, lock.DefinitionHash)
	if err != nil {
		return err
	}
	defer shutdown()

	peerIDs, peerMap := buildPeerMap(peers)
	nodeIdx := peerMap[pID]

	ex := newExchanger(p2pNode, nodeIdx.PeerIdx, peerIDs, []sigType{sigLock}, sigExchangeTimeout)
	caster := bcast.New(p2pNode, peerIDs, key)
	nodeSigCaster := newNodeSigBcast(peers, nodeIdx, caster)

	// register pedersen protocol messages
	pedersenReshareConfig := pedersen.NewReshareConfig(len(lock.Validators), lock.Threshold, nil)
	pedersenConfig := pedersen.NewConfig(p2pNode.ID(), peerMap, lock.Threshold, lock.DefinitionHash, pedersenReshareConfig)
	pedersenBoard := pedersen.NewBoard(ctx, p2pNode, pedersenConfig, caster)

	log.Info(ctx, "Waiting to connect to all peers...")

	nextStepSync, stopSync, err := startSyncProtocol(ctx, p2pNode, key, lock.DefinitionHash, peerIDs, cancel, TestConfig{})
	if err != nil {
		return err
	}

	newShares, err := pedersen.RunReshareDKG(ctx, pedersenConfig, pedersenBoard, shares)
	if err != nil {
		return err
	}

	if err := nextStepSync(ctx); err != nil {
		return errors.Wrap(err, "sync next step")
	}

	// Updating the lock.
	newDef := lock.Definition
	newDef.Creator = cluster.Creator{}

	enrs := make([]string, len(newDef.Operators))
	for i := range newDef.Operators {
		enrs[i] = newDef.Operators[i].ENR
	}

	newDef.Operators = make([]cluster.Operator, len(enrs))
	for i, enr := range enrs {
		newDef.Operators[i] = cluster.Operator{
			ENR: enr,
		}
	}

	newDef, err = newDef.SetDefinitionHashes()
	if err != nil {
		return errors.Wrap(err, "set definition hashes")
	}

	newLock := cluster.Lock{
		Definition: newDef,
		Validators: lock.Validators,
	}

	cshares := copyToShares(newShares)
	for vi := range lock.Validators {
		msg := msgFromShare(cshares[vi])
		lock.Validators[vi].PubShares = msg.PubShares
	}

	newLock, err = newLock.SetLockHash()
	if err != nil {
		return errors.Wrap(err, "set lock hash")
	}

	lockHashSig, err := signLockHash(nodeIdx.ShareIdx, cshares, newLock.LockHash)
	if err != nil {
		return err
	}

	if err := nextStepSync(ctx); err != nil {
		return errors.Wrap(err, "sync next step")
	}

	peerSigs, err := ex.exchange(ctx, sigLock, lockHashSig)
	if err != nil {
		return err
	}

	pubkeyToShares := make(map[core.PubKey]share)
	for _, sh := range cshares {
		pk, err := core.PubKeyFromBytes(sh.PubKey[:])
		if err != nil {
			return err
		}

		pubkeyToShares[pk] = sh
	}

	aggSigLockHash, aggPkLockHash, err := aggLockHashSig(peerSigs, pubkeyToShares, newLock.LockHash)
	if err != nil {
		return err
	}

	if err := tbls.VerifyAggregate(aggPkLockHash, aggSigLockHash, newLock.LockHash); err != nil {
		return errors.Wrap(err, "verify multisignature")
	}

	newLock.SignatureAggregate = aggSigLockHash[:]

	newLock.NodeSignatures, err = nodeSigCaster.exchange(ctx, key, newLock.LockHash)
	if err != nil {
		return errors.Wrap(err, "k1 lock hash signature exchange")
	}

	if err := newLock.VerifySignatures(eth1Cl); err != nil {
		return errors.Wrap(err, "invalid lock file signatures")
	}

	if err = storeKeys(newShares, conf.OutputDir); err != nil {
		return err
	}

	if err = writeLock(conf.OutputDir, newLock); err != nil {
		return err
	}

	if err = stopSync(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return errors.Wrap(err, "sync shutdown")
	}

	log.Debug(ctx, "Graceful shutdown delay", z.Int("seconds", int(conf.DKG.ShutdownDelay.Seconds())))
	time.Sleep(conf.DKG.ShutdownDelay)

	return nil
}

// runPedersenDKG runs the Pedersen DKG protocol using the provided board and configuration.
func runPedersenDKG(ctx context.Context, config *pedersen.Config, board *pedersen.Board, numVals int) ([]share, error) {
	shares, err := pedersen.RunDKG(ctx, config, board, numVals)
	if err != nil {
		return nil, err
	}

	return copyToShares(shares), nil
}

func copyToShares(in []*pedersen.Share) (out []share) {
	out = make([]share, 0, len(in))

	for i := range in {
		out = append(out, share{
			PubKey:       in[i].PubKey,
			SecretShare:  in[i].SecretShare,
			PublicShares: in[i].PublicShares,
		})
	}

	return out
}

func storeKeys(shares []*pedersen.Share, outputDir string) error {
	var newSecrets []tbls.PrivateKey
	for _, s := range shares {
		newSecrets = append(newSecrets, s.SecretShare)
	}

	newKeysDir, err := cluster.CreateValidatorKeysDir(outputDir)
	if err != nil {
		return err
	}

	return keystore.StoreKeys(newSecrets, newKeysDir)
}

func buildPeersList(lock *cluster.Lock, conf *AddOperatorsDKGConfig) ([]p2p.Peer, error) {
	peers, err := lock.Peers()
	if err != nil {
		return nil, err
	}

	// Add new operators to the peer list
	for i, newENR := range conf.NewENRs {
		rec, err := enr.Parse(newENR)
		if err != nil {
			return nil, errors.Wrap(err, "parse enr")
		}

		index := len(lock.Operators) + i

		newPeer, err := p2p.NewPeerFromENR(rec, index)
		if err != nil {
			return nil, errors.Wrap(err, "new peer from enr")
		}

		peers = append(peers, newPeer)
	}

	return peers, nil
}

func buildPeerMap(peers []p2p.Peer) ([]peer.ID, map[peer.ID]cluster.NodeIdx) {
	peerIDs := make([]peer.ID, len(peers))
	peerMap := make(map[peer.ID]cluster.NodeIdx)

	for i, p := range peers {
		peerIDs[i] = p.ID
		peerMap[p.ID] = cluster.NodeIdx{
			PeerIdx:  i,
			ShareIdx: i + 1,
		}
	}

	return peerIDs, peerMap
}
