// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
)

// hashRoot hashes a ssz root hasher object.
func hashRoot(hasher rootHasher) ([32]byte, error) {
	hw := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hw)

	if err := hasher.HashTreeRootWith(hw); err != nil {
		return [32]byte{}, err
	}

	resp, err := hw.HashRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash root")
	}

	return resp, nil
}

// verifyEmptySig verifies that the signed mutation isn't signed.
func verifyEmptySig(signed SignedMutation) error {
	if len(signed.Signature) != 0 {
		return errors.New("non-empty signature")
	}

	if len(signed.Signer) != 0 {
		return errors.New("non-empty signer")
	}

	return nil
}

// verifyK1SignedMutation verifies that the signed mutation is signed by a k1 key.
//
//nolint:unused // Will be used in next PR.
func verifyK1SignedMutation(signed SignedMutation) error {
	pubkey, err := k1.ParsePubKey(signed.Signer)
	if err != nil {
		return errors.Wrap(err, "parse signer pubkey")
	}

	hash, err := hashRoot(signed.Mutation)
	if err != nil {
		return errors.Wrap(err, "hash mutation")
	}

	if signed.Hash != hash {
		return errors.New("signed mutation hash mismatch")
	}

	if ok, err := k1util.Verify(pubkey, hash[:], signed.Signature); err != nil {
		return errors.Wrap(err, "verify signature")
	} else if !ok {
		return errors.New("invalid mutation signature")
	}

	return nil
}
