// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	"time"

	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
)

// NewLegacyLock return a new legacy lock mutation from the provided lock.
func NewLegacyLock(lock cluster.Lock) (SignedMutation, error) {
	timestamp, err := time.Parse(time.RFC3339, lock.Timestamp)
	if err != nil {
		return SignedMutation{}, errors.Wrap(err, "parse lock timestamp")
	}

	m := Mutation{
		Parent:    [32]byte{}, // Empty parent
		Type:      TypeLegacyLock,
		Timestamp: timestamp,
		Data:      lockWrapper{lock},
	}

	hash, err := hashRoot(m)
	if err != nil {
		return SignedMutation{}, errors.Wrap(err, "hash mutation")
	}

	return SignedMutation{
		Mutation: m,
		Hash:     hash,
		// No signer or signature
	}, nil
}

// lockWrapper wraps the lock hash using the lockhash directly as the mutation data hash.
type lockWrapper struct {
	cluster.Lock
}

// HashTreeRootWith writes the lock hash to the hasher.
func (l lockWrapper) HashTreeRootWith(hw ssz.HashWalker) error {
	indx := hw.Index()

	if err := putBytesN(hw, l.Lock.LockHash, 32); err != nil {
		return err
	}

	hw.Merkleize(indx)

	return nil
}

// verifyLegacyLock verifies that the signed mutation is a valid legacy lock.
func verifyLegacyLock(signed SignedMutation) error {
	if signed.Mutation.Type != TypeLegacyLock {
		return errors.New("invalid mutation type")
	}

	if err := verifyEmptySig(signed); err != nil {
		return errors.Wrap(err, "verify empty signature")
	}

	if hash, err := hashRoot(signed.Mutation); err != nil {
		return errors.Wrap(err, "hash mutation")
	} else if signed.Hash != hash {
		return errors.New("signed mutation hash mismatch")
	}

	wrapper, ok := signed.Mutation.Data.(lockWrapper)
	if !ok {
		return errors.New("data not a lock")
	}

	return wrapper.Lock.VerifySignatures()
}

// transformLegacyLock transforms the cluster state with the provided legacy lock mutation.
func transformLegacyLock(_ Cluster, signed SignedMutation) (Cluster, error) {
	if err := verifyLegacyLock(signed); err != nil {
		return Cluster{}, errors.Wrap(err, "verify legacy lock")
	}

	// TODO(corver): Implement legacy lock transform.

	return Cluster{}, nil
}
