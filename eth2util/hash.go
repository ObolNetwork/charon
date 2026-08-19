// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util

import (
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pk910/dynamic-ssz/hasher"

	"github.com/obolnetwork/charon/app/errors"
)

// SlotHashRoot returns the ssz hash root of the slot.
func SlotHashRoot(slot eth2p0.Slot) ([32]byte, error) {
	hh := hasher.DefaultHasherPool.Get()
	defer hasher.DefaultHasherPool.Put(hh)

	indx := hh.Index()

	hh.PutUint64(uint64(slot))

	hh.Merkleize(indx)

	hash, err := hh.HashRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash epoch")
	}

	return hash, nil
}
