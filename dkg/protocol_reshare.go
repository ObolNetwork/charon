// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"path/filepath"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/dkg/pedersen"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
)

type reshareProtocol struct {
	outputDir string
	config    *pedersen.Config
	board     *pedersen.Board
}

var _ Protocol = (*reshareProtocol)(nil)

func newReshareProtocol(outputDir string) *reshareProtocol {
	return &reshareProtocol{
		outputDir: outputDir,
	}
}

func (*reshareProtocol) GetPeers(lock *cluster.Lock) ([]p2p.Peer, error) {
	return lock.Peers()
}

func (p *reshareProtocol) PostInit(ctx context.Context, pctx *ProtocolContext) error {
	// register pedersen protocol messages
	pedersenReshareConfig := pedersen.NewReshareConfig(len(pctx.Lock.Validators), pctx.Lock.Threshold, nil)
	p.config = pedersen.NewConfig(pctx.ThisPeerID, pctx.PeerMap, pctx.Lock.Threshold, pctx.Lock.DefinitionHash, pedersenReshareConfig)
	p.board = pedersen.NewBoard(ctx, pctx.ThisNode, p.config, pctx.Caster)

	return nil
}

func (p *reshareProtocol) Steps() []ProtocolStep {
	return []ProtocolStep{
		&reshareProtocolStep{config: p.config, board: p.board},
		&updateLockProtocolStep{},
		&updateNodeSignaturesProtocolStep{},
		&writeArtifactsProtocolStep{outputDir: p.outputDir},
	}
}

type reshareProtocolStep struct {
	config *pedersen.Config
	board  *pedersen.Board
}

func (s *reshareProtocolStep) Run(ctx context.Context, pctx *ProtocolContext) error {
	shares, err := pedersen.RunReshareDKG(ctx, s.config, s.board, pctx.Shares)
	if err != nil {
		return err
	}

	pctx.Shares = shares

	return nil
}

type updateLockProtocolStep struct {
	newThreshold int
	addOperators []string
}

func (s *updateLockProtocolStep) Run(ctx context.Context, pctx *ProtocolContext) error {
	// We cannot create proper Creator info without EL signature
	var (
		newDef = pctx.Lock.Definition
		err    error
	)

	newDef.Creator = cluster.Creator{}

	// Reset operators info except ENRs for the same reason
	for i := range newDef.Operators {
		newDef.Operators[i] = cluster.Operator{
			ENR: newDef.Operators[i].ENR,
		}
	}

	for _, enr := range s.addOperators {
		newDef.Operators = append(newDef.Operators, cluster.Operator{
			ENR: enr,
		})
	}

	if s.newThreshold > 0 {
		newDef.Threshold = s.newThreshold
	}

	newDef, err = newDef.SetDefinitionHashes()
	if err != nil {
		return errors.Wrap(err, "set definition hashes")
	}

	newLock := cluster.Lock{
		Definition: newDef,
		Validators: pctx.Lock.Validators,
	}

	// Validators pub shares are updated due to the new key shares
	cshares := copyToShares(pctx.Shares)
	for vi := range pctx.Lock.Validators {
		msg := msgFromShare(cshares[vi])
		newLock.Validators[vi].PubShares = msg.PubShares
	}

	newLock, err = newLock.SetLockHash()
	if err != nil {
		return errors.Wrap(err, "set lock hash")
	}

	lockHashSig, err := signLockHash(pctx.ThisNodeIdx.ShareIdx, cshares, newLock.LockHash)
	if err != nil {
		return err
	}

	// Exchanging the lock hash signatures
	peerSigs, err := pctx.SigExchanger.exchange(ctx, sigLock, lockHashSig)
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
		return errors.Wrap(err, "verify lock hash signature")
	}

	newLock.SignatureAggregate = aggSigLockHash[:]
	pctx.Lock = &newLock

	return nil
}

type updateNodeSignaturesProtocolStep struct{}

func (*updateNodeSignaturesProtocolStep) Run(ctx context.Context, pctx *ProtocolContext) (err error) {
	pctx.Lock.NodeSignatures, err = pctx.NodeSigCaster.exchange(ctx, pctx.ENRPrivateKey, pctx.Lock.LockHash)
	if err != nil {
		return errors.Wrap(err, "k1 lock hash signature exchange")
	}

	if err := pctx.Lock.VerifySignatures(pctx.ETH1Client); err != nil {
		return errors.Wrap(err, "invalid lock file signatures")
	}

	return nil
}

type writeArtifactsProtocolStep struct {
	outputDir string
}

func (s *writeArtifactsProtocolStep) Run(ctx context.Context, pctx *ProtocolContext) error {
	if err := app.CreateNewEmptyDir(s.outputDir); err != nil {
		return err
	}

	if err := app.CopyFile(filepath.Join(pctx.Config.DataDir, enrPrivateKeyFile), filepath.Join(s.outputDir, enrPrivateKeyFile)); err != nil {
		return err
	}

	if err := storeKeys(pctx.Shares, s.outputDir); err != nil {
		return err
	}

	if err := writeLock(s.outputDir, *pctx.Lock); err != nil {
		return err
	}

	log.Info(ctx, "Stored artifacts", z.Str("output_dir", s.outputDir))

	return nil
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
