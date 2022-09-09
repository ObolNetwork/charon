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

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// Lock extends the cluster config Definition with bls threshold public keys and checksums.
type Lock struct {
	// Definition is embedded and extended by Lock.
	Definition `json:"cluster_definition" ssz:"Composite" lock_hash:"0"`

	// Validators are the distributed validators (n*32ETH) managed by the cluster.
	Validators []DistValidator `json:"distributed_validators" ssz:"Composite[65536]" lock_hash:"1"`

	// LockHash uniquely identifies a cluster lock.
	LockHash []byte `json:"lock_hash" ssz:"Bytes32" lock_hash:"-"`

	// SignatureAggregate is the bls aggregate signature of the lock hash signed by
	// all the private key shares of all the distributed validators.
	// It acts as an attestation by all the distributed validators
	// of the charon cluster they are part of.
	SignatureAggregate []byte `json:"signature_aggregate" ssz:"Bytes96" lock_hash:"-"`
}

func (l Lock) MarshalJSON() ([]byte, error) {
	// Marshal lock hash
	lockHash, err := hashLock(l)
	if err != nil {
		return nil, errors.Wrap(err, "hash lock")
	}

	switch {
	case isJSONv1x0(l.Version) || isJSONv1x1(l.Version):
		return marshalLockV1x0or1(l, lockHash)
	case isJSONv1x2(l.Version) || isJSONv1x3(l.Version):
		return marshalLockV1x2or3(l, lockHash)
	default:
		return nil, errors.New("unsupported version")
	}
}

func (l *Lock) UnmarshalJSON(data []byte) error {
	// Get the version directly
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
		lock Lock
		err  error
	)
	switch {
	case isJSONv1x0(version.Definition.Version) || isJSONv1x1(version.Definition.Version):
		lock, err = unmarshalLockV1x0or1(data)
		if err != nil {
			return err
		}
	case isJSONv1x2(version.Definition.Version) || isJSONv1x3(version.Definition.Version):
		lock, err = unmarshalLockV1x2or3(data)
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported version")
	}

	hash, err := hashLock(lock)
	if err != nil {
		return errors.Wrap(err, "hash lock")
	}

	if !bytes.Equal(lock.LockHash, hash[:]) {
		return errors.New("invalid lock hash")
	}

	*l = lock

	return nil
}

// SetLockHash returns a copy of the lock with the lock hash populated.
func (l Lock) SetLockHash() (Lock, error) {
	lockHash, err := hashLock(l)
	if err != nil {
		return Lock{}, err
	}

	l.LockHash = lockHash[:]

	return l, nil
}

// Verify returns true if all config signatures are fully populated and valid.
// A verified lock is ready for use in charon run.
func (l Lock) Verify() error {
	if err := l.Definition.Verify(); err != nil {
		return errors.Wrap(err, "invalid definition")
	}

	if len(l.SignatureAggregate) == 0 {
		if isJSONv1x0(l.Version) || isJSONv1x1(l.Version) {
			return nil // Earlier versions of `charon create cluster` didn't populate SignatureAggregate.
		}

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

	hash, err := hashLock(l)
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

func marshalLockV1x0or1(lock Lock, lockHash [32]byte) ([]byte, error) {
	resp, err := json.Marshal(lockJSONv1x0or1{
		Definition:         lock.Definition,
		Validators:         distValidatorsToV1x1(lock.Validators),
		SignatureAggregate: lock.SignatureAggregate,
		LockHash:           lockHash[:],
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal definition v1_1")
	}

	return resp, nil
}

func marshalLockV1x2or3(lock Lock, lockHash [32]byte) ([]byte, error) {
	resp, err := json.Marshal(lockJSONv1x2or3{
		Definition:         lock.Definition,
		Validators:         distValidatorsToV1x2or3(lock.Validators),
		SignatureAggregate: lock.SignatureAggregate,
		LockHash:           lockHash[:],
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal definition v1_2")
	}

	return resp, nil
}

func unmarshalLockV1x0or1(data []byte) (lock Lock, err error) {
	var lockJSON lockJSONv1x0or1
	if err := json.Unmarshal(data, &lockJSON); err != nil {
		return Lock{}, errors.Wrap(err, "unmarshal definition")
	}

	lock = Lock{
		Definition:         lockJSON.Definition,
		Validators:         distValidatorsFromV1x1(lockJSON.Validators),
		SignatureAggregate: lockJSON.SignatureAggregate,
		LockHash:           lockJSON.LockHash,
	}

	return lock, nil
}

func unmarshalLockV1x2or3(data []byte) (lock Lock, err error) {
	var lockJSON lockJSONv1x2or3
	if err := json.Unmarshal(data, &lockJSON); err != nil {
		return Lock{}, errors.Wrap(err, "unmarshal definition")
	}

	lock = Lock{
		Definition:         lockJSON.Definition,
		Validators:         distValidatorsFromV1x2or3(lockJSON.Validators),
		SignatureAggregate: lockJSON.SignatureAggregate,
		LockHash:           lockJSON.LockHash,
	}

	return lock, nil
}

// lockJSONv1x0or1 is the json formatter of Lock for versions v1.0.0 and v1.1.0.
type lockJSONv1x0or1 struct {
	Definition         Definition              `json:"cluster_definition"`
	Validators         []distValidatorJSONv1x1 `json:"distributed_validators"`
	SignatureAggregate []byte                  `json:"signature_aggregate"`
	LockHash           []byte                  `json:"lock_hash"`
}

// lockJSONv1x2or3 is the json formatter of Lock for versions v1.2.0 and later.
type lockJSONv1x2or3 struct {
	Definition         Definition              `json:"cluster_definition"`
	Validators         []distValidatorJSONv1x2 `json:"distributed_validators"`
	SignatureAggregate ethHex                  `json:"signature_aggregate"`
	LockHash           ethHex                  `json:"lock_hash"`
}
