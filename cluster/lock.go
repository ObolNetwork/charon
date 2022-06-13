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

package cluster

import (
	"bytes"
	"encoding/json"

	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
)

// Lock extends the cluster config Definition with bls threshold public keys and checksums.
type Lock struct {
	// Definition is embedded and extended by Lock.
	Definition

	// Validators are the distributed validators (n*32ETH) managed by the cluster.
	Validators []DistValidator

	// SignatureAggregate is the bls aggregate signature of the lock hash signed by each DV pubkey.
	// It acts as an attestation by all the distributed validators of the charon cluster they are part of.
	SignatureAggregate []byte
}

// HashTreeRoot ssz hashes the Lock object.
func (l Lock) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(l) //nolint:wrapcheck
}

// HashTreeRootWith ssz hashes the Lock object with a hasher.
func (l Lock) HashTreeRootWith(hh *ssz.Hasher) error {
	indx := hh.Index()

	// Field (0) 'Definition'
	if err := l.Definition.HashTreeRootWith(hh); err != nil {
		return err
	}

	// Field (1) 'Validators'
	{
		subIndx := hh.Index()
		num := uint64(len(l.Validators))
		for _, validator := range l.Validators {
			if err := validator.HashTreeRootWith(hh); err != nil {
				return err
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, num)
	}

	hh.Merkleize(indx)

	return nil
}

func (l Lock) MarshalJSON() ([]byte, error) {
	// Marshal lock hash
	hash, err := l.HashTreeRoot()
	if err != nil {
		return nil, errors.Wrap(err, "hash lock")
	}

	// Marshal json version of lock
	resp, err := json.Marshal(lockFmt{
		Definition:         l.Definition,
		Validators:         l.Validators,
		SignatureAggregate: l.SignatureAggregate,
		LockHash:           hash[:],
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal lock")
	}

	return resp, nil
}

func (l *Lock) UnmarshalJSON(data []byte) error {
	// Get the version directly
	version := struct {
		Definition struct { //nolint:revive // Nested struct is read-only.
			Version string `json:"version"`
		} `json:"cluster_definition"`
	}{}
	if err := json.Unmarshal(data, &version); err != nil {
		return errors.Wrap(err, "unmarshal version")
	} else if version.Definition.Version != definitionVersion {
		return errors.Wrap(err, "invalid definition version")
	}

	var lockFmt lockFmt
	if err := json.Unmarshal(data, &lockFmt); err != nil {
		return errors.Wrap(err, "unmarshal definition")
	}

	lock := Lock{
		Definition:         lockFmt.Definition,
		Validators:         lockFmt.Validators,
		SignatureAggregate: lockFmt.SignatureAggregate,
	}

	hash, err := lock.HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "hash lock")
	}

	if !bytes.Equal(lockFmt.LockHash, hash[:]) {
		return errors.New("invalid lock hash")
	}

	*l = lock

	return nil
}

// lockFmt is the json formatter of Lock.
type lockFmt struct {
	Definition         Definition      `json:"cluster_definition"`
	Validators         []DistValidator `json:"distributed_validators"`
	SignatureAggregate []byte          `json:"signature_aggregate"`
	LockHash           []byte          `json:"lock_hash"`
}
