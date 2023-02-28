// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	//nolint:gosimple
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
