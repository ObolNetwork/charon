// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util

import (
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
)

// SlotHashRoot returns the ssz hash root of the slot.
func SlotHashRoot(slot eth2p0.Slot) ([32]byte, error) {
	hasher := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hasher)

	indx := hasher.Index()

	hasher.PutUint64(uint64(slot))

	hasher.Merkleize(indx)

	hash, err := hasher.HashRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash epoch")
	}

	return hash, nil
}
