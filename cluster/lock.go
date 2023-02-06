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

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
	tblsconv2 "github.com/obolnetwork/charon/tbls/v2/tblsconv"
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
	case isV1x0(l.Version) || isV1x1(l.Version):
		return marshalLockV1x0or1(l, lockHash)
	case isV1x2(l.Version) || isV1x3(l.Version) || isV1x4(l.Version) || isV1x5(l.Version):
		return marshalLockV1x2orLater(l, lockHash)
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
	case isAnyVersion(version.Definition.Version, v1_0, v1_1):
		lock, err = unmarshalLockV1x0or1(data)
		if err != nil {
			return err
		}
	case isAnyVersion(version.Definition.Version, v1_2, v1_3, v1_4, v1_5):
		lock, err = unmarshalLockV1x2orLater(data)
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported version")
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

// VerifyHashes returns an error if hashes populated from json object doesn't matches actual hashes.
func (l Lock) VerifyHashes() error {
	if err := l.Definition.VerifyHashes(); err != nil {
		return errors.Wrap(err, "invalid definition")
	}

	lockHash, err := hashLock(l)
	if err != nil {
		return err
	}

	if !bytes.Equal(l.LockHash, lockHash[:]) {
		return errors.New("invalid lock hash")
	}

	return nil
}

// VerifySignatures returns true if all config signatures are fully populated and valid.
// A verified lock is ready for use in charon run.
func (l Lock) VerifySignatures() error {
	if err := l.Definition.VerifySignatures(); err != nil {
		return errors.Wrap(err, "invalid definition")
	}

	if len(l.SignatureAggregate) == 0 {
		if isV1x0(l.Version) || isV1x1(l.Version) {
			return nil // Earlier versions of `charon create cluster` didn't populate SignatureAggregate.
		}

		return errors.New("empty lock aggregate signature")
	}

	sig, err := tblsconv2.SignatureFromBytes(l.SignatureAggregate)
	if err != nil {
		return err
	}

	var pubkeys []tblsv2.PublicKey
	for _, val := range l.Validators {
		for _, share := range val.PubShares {
			pubkey, err := tblsconv2.PubkeyFromBytes(share)
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

	err = tblsv2.VerifyAggregate(pubkeys, sig, hash[:])
	if err != nil {
		return errors.Wrap(err, "verify lock signature aggregate")
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

func marshalLockV1x2orLater(lock Lock, lockHash [32]byte) ([]byte, error) {
	resp, err := json.Marshal(lockJSONv1x2orLater{
		Definition:         lock.Definition,
		Validators:         distValidatorsToV1x2orLater(lock.Validators),
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

	for _, validator := range lockJSON.Validators {
		if len(validator.FeeRecipientAddress) > 0 {
			return Lock{}, errors.New("distributed validator fee recipient not supported anymore")
		}
	}

	lock = Lock{
		Definition:         lockJSON.Definition,
		Validators:         distValidatorsFromV1x1(lockJSON.Validators),
		SignatureAggregate: lockJSON.SignatureAggregate,
		LockHash:           lockJSON.LockHash,
	}

	return lock, nil
}

func unmarshalLockV1x2orLater(data []byte) (lock Lock, err error) {
	var lockJSON lockJSONv1x2orLater
	if err := json.Unmarshal(data, &lockJSON); err != nil {
		return Lock{}, errors.Wrap(err, "unmarshal definition")
	}

	for _, validator := range lockJSON.Validators {
		if len(validator.FeeRecipientAddress) > 0 {
			return Lock{}, errors.New("distributed validator fee recipient not supported anymore")
		}
	}

	lock = Lock{
		Definition:         lockJSON.Definition,
		Validators:         distValidatorsFromV1x2orLater(lockJSON.Validators),
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

// lockJSONv1x2orLater is the json formatter of Lock for versions v1.2.0 and later.
type lockJSONv1x2orLater struct {
	Definition         Definition              `json:"cluster_definition"`
	Validators         []distValidatorJSONv1x2 `json:"distributed_validators"`
	SignatureAggregate ethHex                  `json:"signature_aggregate"`
	LockHash           ethHex                  `json:"lock_hash"`
}
