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
	"strings"

	"github.com/obolnetwork/charon/app/errors"
)

func (s Spec) MarshalJSON() ([]byte, error) {
	type fieldsOnly Spec // Marshal fields-only version of spec
	specBytes, err := json.Marshal(fieldsOnly(s))
	if err != nil {
		return nil, errors.Wrap(err, "marshal spec")
	}

	// Marshal spec hash
	hash, err := s.HashTreeRoot()
	if err != nil {
		return nil, errors.Wrap(err, "hash spec")
	}

	hashBytes, err := json.Marshal(struct {
		Hash []byte `json:"spec_hash"`
	}{Hash: hash[:]})
	if err != nil {
		return nil, errors.Wrap(err, "marshal spec hash")
	}

	// Manually append spec hash field to retain json field order.
	resp := strings.TrimSuffix(string(specBytes), "}")
	resp += ","
	resp += strings.TrimPrefix(string(hashBytes), "{")

	return []byte(resp), nil
}

func (s *Spec) UnmarshalJSON(data []byte) error {
	// Get the version directly
	version := struct {
		Version string `json:"version"`
	}{}
	if err := json.Unmarshal(data, &version); err != nil {
		return errors.Wrap(err, "unmarshal version")
	} else if version.Version != specVersion {
		return errors.Wrap(err, "invalid spec version")
	}

	// Unmarshal a fields-only spec version.
	type fieldsOnly Spec
	var fields fieldsOnly
	if err := json.Unmarshal(data, &fields); err != nil {
		return errors.Wrap(err, "unmarshal spec")
	}

	// Get the spec hash directly
	specHash := struct {
		Hash []byte `json:"spec_hash"`
	}{}
	if err := json.Unmarshal(data, &specHash); err != nil {
		return errors.Wrap(err, "unmarshal spec hash")
	}

	// Validate spec hash
	hash, err := Spec(fields).HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "hash spec")
	}
	if !bytes.Equal(specHash.Hash, hash[:]) {
		return errors.New("invalid spec hash")
	}

	*s = Spec(fields)

	return nil
}

type lockJSON struct {
	Spec               Spec            `json:"cluster_spec"`
	Validators         []DistValidator `json:"distributed_validators"`
	SignatureAggregate []byte          `json:"signature_aggregate"`
	LockHash           []byte          `json:"lock_hash"`
}

func (l Lock) MarshalJSON() ([]byte, error) {
	// Marshal lock hash
	hash, err := l.HashTreeRoot()
	if err != nil {
		return nil, errors.Wrap(err, "hash lock")
	}

	// Marshal json version of lock
	resp, err := json.Marshal(lockJSON{
		Spec:               l.Spec,
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
		Spec struct { //nolint:revive // Nested struct is read-only.
			Version string `json:"version"`
		} `json:"cluster_spec"`
	}{}
	if err := json.Unmarshal(data, &version); err != nil {
		return errors.Wrap(err, "unmarshal version")
	} else if version.Spec.Version != specVersion {
		return errors.Wrap(err, "invalid spec version")
	}

	var lockJSON lockJSON
	if err := json.Unmarshal(data, &lockJSON); err != nil {
		return errors.Wrap(err, "unmarshal spec")
	}

	lock := Lock{
		Spec:               lockJSON.Spec,
		Validators:         lockJSON.Validators,
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
