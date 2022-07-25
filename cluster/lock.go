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
	"github.com/obolnetwork/charon/app/z"
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
	lockHash, err := l.HashTreeRoot()
	if err != nil {
		return nil, errors.Wrap(err, "hash lock")
	}

	if isJSONv1x1(l.Version) { //nolint:nestif
		vals, err := distValidatorsToV1x1(l.Validators)
		if err != nil {
			return nil, err
		}
		resp, err := json.Marshal(lockJSONv1x1{
			Definition:         l.Definition,
			Validators:         vals,
			SignatureAggregate: l.SignatureAggregate,
			LockHash:           lockHash[:],
		})
		if err != nil {
			return nil, errors.Wrap(err, "marshal definition v1_1")
		}

		return resp, nil
	} else if isJSONv1x2(l.Version) { //nolint:revive
		vals, err := distValidatorsToV1x2(l.Validators)
		if err != nil {
			return nil, err
		}
		resp, err := json.Marshal(lockJSONv1x2{
			Definition:         l.Definition,
			Validators:         vals,
			SignatureAggregate: l.SignatureAggregate,
			LockHash:           lockHash[:],
		})
		if err != nil {
			return nil, errors.Wrap(err, "marshal definition v1_2")
		}

		return resp, nil
	} else {
		return nil, errors.New("unsupported version")
	}
}

func (l *Lock) UnmarshalJSON(data []byte) error {
	// Get the version directly
	//nolint:revive // Nested structs fine for reading.
	version := struct {
		Definition struct {
			Version string `json:"version"`
		} `json:"cluster_definition"`
	}{}
	if err := json.Unmarshal(data, &version); err != nil {
		return errors.Wrap(err, "unmarshal version")
	} else if !supportedVersions[version.Definition.Version] {
		return errors.New("unsupported definition version",
			z.Str("version", version.Definition.Version),
			z.Any("supported", supportedVersions),
		)
	}

	if isJSONv1x1(version.Definition.Version) {
		return l.unmarshalV1x1(data)
	} else if isJSONv1x2(version.Definition.Version) {
		return l.unmarshalV1x2(data)
	} else {
		return errors.New("unsupported version")
	}
}

func (l *Lock) unmarshalV1x1(data []byte) error {
	var lockJSON lockJSONv1x1
	if err := json.Unmarshal(data, &lockJSON); err != nil {
		return errors.Wrap(err, "unmarshal definition")
	}

	lock := Lock{
		Definition:         lockJSON.Definition,
		Validators:         distValidatorsFromV1x1(lockJSON.Validators),
		SignatureAggregate: lockJSON.SignatureAggregate,
	}

	hash, err := lock.HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "hash lock")
	}

	if !bytes.Equal(lockJSON.LockHash, hash[:]) {
		return errors.New("invalid lock hash")
	}

	*l = lock

	return nil
}

func (l *Lock) unmarshalV1x2(data []byte) error {
	var lockJSON lockJSONv1x2
	if err := json.Unmarshal(data, &lockJSON); err != nil {
		return errors.Wrap(err, "unmarshal definition")
	}

	lock := Lock{
		Definition:         lockJSON.Definition,
		Validators:         distValidatorsFromV1x2(lockJSON.Validators),
		SignatureAggregate: lockJSON.SignatureAggregate,
	}

	hash, err := lock.HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "hash lock")
	}

	if !bytes.Equal(lockJSON.LockHash, hash[:]) {
		return errors.New("invalid lock hash")
	}

	*l = lock

	return nil
}

// lockJSONv1x1 is the json formatter of Lock for versions v1.0.0 and v1.1.0.
type lockJSONv1x1 struct {
	Definition         Definition              `json:"cluster_definition"`
	Validators         []distValidatorJSONv1x1 `json:"distributed_validators"`
	SignatureAggregate []byte                  `json:"signature_aggregate"`
	LockHash           []byte                  `json:"lock_hash"`
}

// lockJSONv1x2 is the json formatter of Lock for versions v1.2.0 and later.
type lockJSONv1x2 struct {
	Definition         Definition              `json:"cluster_definition"`
	Validators         []distValidatorJSONv1x2 `json:"distributed_validators"`
	SignatureAggregate base58                  `json:"signature_aggregate"`
	LockHash           base58                  `json:"lock_hash"`
}
