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

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// Lock extends the cluster config Definition with bls threshold public keys and checksums.
type Lock struct {
	// Definition is embedded and extended by Lock.
	Definition

	// Validators are the distributed validators (n*32ETH) managed by the cluster.
	Validators []DistValidator

	// SignatureAggregate is the bls aggregate signature of the lock hash signed by
	// all the private key shares of all the distributed validators.
	// It acts as an attestation by all the distributed validators
	// of the charon cluster they are part of.
	SignatureAggregate []byte
}

// GetTree ssz hashes the Lock object.
func (l Lock) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(l) //nolint:wrapcheck
}

// HashTreeRoot ssz hashes the Lock object.
func (l Lock) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(l) //nolint:wrapcheck
}

// HashTreeRootWith ssz hashes the Lock object with a hasher.
func (l Lock) HashTreeRootWith(hh ssz.HashWalker) error {
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

	switch {
	case isJSONv1x1(l.Version):
		return marshalLockV1x1(l, lockHash)
	case isJSONv1x2(l.Version):
		return marshalLockV1x2(l, lockHash)
	default:
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

	var (
		lock         Lock
		lockHashJSON []byte
		err          error
	)
	switch {
	case isJSONv1x1(version.Definition.Version):
		lock, lockHashJSON, err = unmarshalLockV1x1(data)
		if err != nil {
			return err
		}
	case isJSONv1x2(version.Definition.Version):
		lock, lockHashJSON, err = unmarshalLockV1x2(data)
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported version")
	}

	hash, err := lock.HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "hash lock")
	}

	if !bytes.Equal(lockHashJSON, hash[:]) {
		return errors.New("invalid lock hash")
	}

	*l = lock

	return nil
}

// Verify returns true if all config signatures are fully populated and valid.
// A verified lock is ready for use in charon run.
func (l Lock) Verify() error {
	if err := l.Definition.Verify(); err != nil {
		return errors.Wrap(err, "invalid definition")
	}

	if len(l.SignatureAggregate) == 0 {
		return errors.New("empty lock aggregate signature")
	}

	sig, err := tblsconv.SigFromBytes(l.SignatureAggregate)
	if err != nil {
		return err
	}

	var pubkeys []*bls_sig.PublicKey
	for _, val := range l.Validators {
		for _, share := range val.PubShares {
			pubkey, err := tblsconv.KeyFromBytes(share)
			if err != nil {
				return err
			}
			pubkeys = append(pubkeys, pubkey)
		}
	}

	hash, err := l.HashTreeRoot()
	if err != nil {
		return err
	}

	ok, err := tbls.Scheme().FastAggregateVerify(pubkeys, hash[:], sig)
	if err != nil {
		return errors.Wrap(err, "verify lock signature aggregate")
	} else if !ok {
		return errors.New("invalid lock signature aggregate")
	}

	return nil
}

func marshalLockV1x1(lock Lock, lockHash [32]byte) ([]byte, error) {
	vals, err := distValidatorsToV1x1(lock.Validators)
	if err != nil {
		return nil, err
	}
	resp, err := json.Marshal(lockJSONv1x1{
		Definition:         lock.Definition,
		Validators:         vals,
		SignatureAggregate: lock.SignatureAggregate,
		LockHash:           lockHash[:],
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal definition v1_1")
	}

	return resp, nil
}

func marshalLockV1x2(lock Lock, lockHash [32]byte) ([]byte, error) {
	vals, err := distValidatorsToV1x2(lock.Validators)
	if err != nil {
		return nil, err
	}
	resp, err := json.Marshal(lockJSONv1x2{
		Definition:         lock.Definition,
		Validators:         vals,
		SignatureAggregate: lock.SignatureAggregate,
		LockHash:           lockHash[:],
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal definition v1_2")
	}

	return resp, nil
}

func unmarshalLockV1x1(data []byte) (lock Lock, lockHashJSON []byte, err error) {
	var lockJSON lockJSONv1x1
	if err := json.Unmarshal(data, &lockJSON); err != nil {
		return Lock{}, nil, errors.Wrap(err, "unmarshal definition")
	}

	lock = Lock{
		Definition:         lockJSON.Definition,
		Validators:         distValidatorsFromV1x1(lockJSON.Validators),
		SignatureAggregate: lockJSON.SignatureAggregate,
	}

	return lock, lockJSON.LockHash, nil
}

func unmarshalLockV1x2(data []byte) (lock Lock, lockHashJSON []byte, err error) {
	var lockJSON lockJSONv1x2
	if err := json.Unmarshal(data, &lockJSON); err != nil {
		return Lock{}, nil, errors.Wrap(err, "unmarshal definition")
	}

	lock = Lock{
		Definition:         lockJSON.Definition,
		Validators:         distValidatorsFromV1x2(lockJSON.Validators),
		SignatureAggregate: lockJSON.SignatureAggregate,
	}

	return lock, lockJSON.LockHash, nil
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
	SignatureAggregate ethHex                  `json:"signature_aggregate"`
	LockHash           ethHex                  `json:"lock_hash"`
}
