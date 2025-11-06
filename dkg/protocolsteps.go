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
	"github.com/obolnetwork/charon/dkg/share"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
)

// noopProtocolStep is a no-op implementation of ProtocolStep.
// A node can decide to do nothing for a step, but still synchronize with other nodes.
type noopProtocolStep struct{}

func (*noopProtocolStep) Run(context.Context, *ProtocolContext) error {
	return nil
}

// reshareProtocolStep runs a resharing DKG to update key shares while keeping the same public key.
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

// ignoreNodeSignaturesProtocolStep is used by nodes excluded from the cluster after DKG.
type ignoreNodeSignaturesProtocolStep struct{}

func (*ignoreNodeSignaturesProtocolStep) Run(ctx context.Context, pctx *ProtocolContext) error {
	// This broadcasts a nil signature to be ignored by assembling nodes.
	// TLDR; we use the same bcast component twice: for DKG and for node signature exchange.
	// For DKG we want all nodes to participate, but for node signatures we want only the
	// remaining nodes to participate.
	// We cannot create two bcast components because they both use the same protocol ID.
	_, err := pctx.NodeSigCaster.exchange(ctx, nil, nil)

	return err
}

// updateLockProtocolStep updates the cluster lock with new operators, threshold and validators.
type updateLockProtocolStep struct {
	threshold int
	operators []string
}

func (s *updateLockProtocolStep) Run(ctx context.Context, pctx *ProtocolContext) error {
	// We cannot create proper Creator info without EL signature
	var (
		newDef = pctx.Lock.Definition
		err    error
	)

	newDef.Creator = cluster.Creator{}

	// Reset operators info except ENRs for the same reason
	if len(s.operators) == 0 {
		for i := range newDef.Operators {
			s.operators = append(s.operators, newDef.Operators[i].ENR)
		}
	}

	newDef.Operators = nil
	for _, enr := range s.operators {
		newDef.Operators = append(newDef.Operators, cluster.Operator{
			ENR: enr,
		})
	}

	if s.threshold > 0 {
		newDef.Threshold = s.threshold
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
	for vi := range pctx.Lock.Validators {
		msg := share.MsgFromShare(pctx.Shares[vi])
		newLock.Validators[vi].PubShares = msg.PubShares
	}

	newLock, err = newLock.SetLockHash()
	if err != nil {
		return errors.Wrap(err, "set lock hash")
	}

	lockHashSig, err := signLockHash(pctx.ThisNodeIdx.ShareIdx, pctx.Shares, newLock.LockHash)
	if err != nil {
		return err
	}

	// Exchanging the lock hash signatures
	peerSigs, err := pctx.SigExchanger.exchange(ctx, sigLock, lockHashSig)
	if err != nil {
		return err
	}

	pubkeyToShares := make(map[core.PubKey]share.Share)

	for _, sh := range pctx.Shares {
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

// updateNodeSignaturesProtocolStep updates the cluster lock with node signatures over the lock hash.
type updateNodeSignaturesProtocolStep struct{}

func (*updateNodeSignaturesProtocolStep) Run(ctx context.Context, pctx *ProtocolContext) error {
	nodeSigs, err := pctx.NodeSigCaster.exchange(ctx, pctx.ENRPrivateKey, pctx.Lock.LockHash)
	if err != nil {
		return errors.Wrap(err, "k1 lock hash signature exchange")
	}

	pctx.Lock.NodeSignatures = nodeSigs

	return pctx.Lock.VerifySignatures(pctx.ETH1Client)
}

// writeArtifactsProtocolStep writes the DKG artifacts to the given output directory:
// the enr private key, the cluster lock and the private key shares.
type writeArtifactsProtocolStep struct {
	outputDir string
}

func (s *writeArtifactsProtocolStep) Run(ctx context.Context, pctx *ProtocolContext) error {
	if err := app.CreateNewEmptyDir(s.outputDir); err != nil {
		return err
	}

	if err := app.CopyFile(pctx.PrivateKeyPath, filepath.Join(s.outputDir, enrPrivateKeyFile)); err != nil {
		return err
	}

	if err := storeKeys(s.outputDir, pctx.Shares); err != nil {
		return err
	}

	if err := writeLock(s.outputDir, *pctx.Lock); err != nil {
		return err
	}

	log.Info(ctx, "Stored artifacts", z.Str("output_dir", s.outputDir))

	return nil
}

func storeKeys(outputDir string, shares []share.Share) error {
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
