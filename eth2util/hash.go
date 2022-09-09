// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package eth2util

import (
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	"github.com/minio/sha256-simd"

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

// SHA256 calculates the sha256 checksum of the input data. https://github.com/ethereum/consensus-specs/blob/v0.9.3/specs/core/0_beacon-chain.md#hash
func SHA256(data []byte) [32]byte {
	h := sha256.New()

	// Write method in the Hash interface never returns an error, so the error isn't handled. See: https://pkg.go.dev/hash#Hash
	_, _ = h.Write(data)

	var b [32]byte
	copy(b[:], h.Sum(nil))

	return b
}
