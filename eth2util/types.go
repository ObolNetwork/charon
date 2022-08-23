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
	"encoding/json"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
)

// SignedEpoch represents signature of corresponding epoch.
type SignedEpoch struct {
	Epoch     eth2p0.Epoch
	Signature eth2p0.BLSSignature
}

// GetTree ssz hashes the SignedEpoch object.
func (s SignedEpoch) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(s) //nolint:wrapcheck
}

// HashTreeRoot ssz hashes the SignedEpoch object.
func (s SignedEpoch) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(s) //nolint:wrapcheck
}

// HashTreeRootWith ssz hashes the epoch from SignedEpoch.
func (s SignedEpoch) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	hh.PutUint64(uint64(s.Epoch))

	hh.Merkleize(indx)

	return nil
}

func (s SignedEpoch) MarshalJSON() ([]byte, error) {
	resp, err := json.Marshal(signedEpochJSON{
		Epoch:     s.Epoch,
		Signature: s.Signature,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal signed epoch")
	}

	return resp, nil
}

func (s *SignedEpoch) UnmarshalJSON(b []byte) error {
	var resp signedEpochJSON
	if err := json.Unmarshal(b, &resp); err != nil {
		return errors.Wrap(err, "unmarshal signed epoch")
	}

	s.Epoch = resp.Epoch
	s.Signature = resp.Signature

	return nil
}

type signedEpochJSON struct {
	Epoch     eth2p0.Epoch        `json:"epoch"`
	Signature eth2p0.BLSSignature `json:"signature"`
}
