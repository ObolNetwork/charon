package eth2util

import (
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	"github.com/obolnetwork/charon/app/errors"
)

// MerkleEpoch wraps epoch to implement ssz.HashRoot.
type MerkleEpoch eth2p0.Epoch

func (m MerkleEpoch) HashTreeRoot() ([32]byte, error) {
	b, err := ssz.HashWithDefaultHasher(m)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash default epoch")
	}

	return b, nil
}

func (m MerkleEpoch) HashTreeRootWith(hh *ssz.Hasher) error {
	indx := hh.Index()

	// Field (1) 'Epoch'
	hh.PutUint64(uint64(m))

	hh.Merkleize(indx)

	return nil
}
