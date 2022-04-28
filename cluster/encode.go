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

func (s Params) MarshalJSON() ([]byte, error) {
	type fieldsOnly Params // Marshal fields-only version of params
	paramsBytes, err := json.Marshal(fieldsOnly(s))
	if err != nil {
		return nil, errors.Wrap(err, "marshal params")
	}

	// Marshal params hash
	hash, err := s.HashTreeRoot()
	if err != nil {
		return nil, errors.Wrap(err, "hash params")
	}

	hashBytes, err := json.Marshal(struct {
		Hash []byte `json:"params_hash"`
	}{Hash: hash[:]})
	if err != nil {
		return nil, errors.Wrap(err, "marshal params hash")
	}

	// Manually append params hash field to retain json field order.
	resp := strings.TrimSuffix(string(paramsBytes), "}")
	resp += ","
	resp += strings.TrimPrefix(string(hashBytes), "{")

	return []byte(resp), nil
}

func (s *Params) UnmarshalJSON(data []byte) error {
	// Get the version directly
	version := struct {
		Version string `json:"version"`
	}{}
	if err := json.Unmarshal(data, &version); err != nil {
		return errors.Wrap(err, "unmarshal version")
	} else if version.Version != paramsVersion {
		return errors.Wrap(err, "invalid params version")
	}

	// Unmarshal a fields-only params version.
	type fieldsOnly Params
	var fields fieldsOnly
	if err := json.Unmarshal(data, &fields); err != nil {
		return errors.Wrap(err, "unmarshal params")
	}

	// Get the params hash directly
	paramsHash := struct {
		Hash []byte `json:"params_hash"`
	}{}
	if err := json.Unmarshal(data, &paramsHash); err != nil {
		return errors.Wrap(err, "unmarshal params hash")
	}

	// Validate params hash
	hash, err := Params(fields).HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "hash params")
	}
	if !bytes.Equal(paramsHash.Hash, hash[:]) {
		return errors.New("invalid params hash")
	}

	*s = Params(fields)

	return nil
}

// lockJSON is the json formatter of Lock.
type lockJSON struct {
	Params             Params          `json:"cluster_params"`
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
		Params:             l.Params,
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
		Params struct { //nolint:revive // Nested struct is read-only.
			Version string `json:"version"`
		} `json:"cluster_params"`
	}{}
	if err := json.Unmarshal(data, &version); err != nil {
		return errors.Wrap(err, "unmarshal version")
	} else if version.Params.Version != paramsVersion {
		return errors.Wrap(err, "invalid params version")
	}

	var lockJSON lockJSON
	if err := json.Unmarshal(data, &lockJSON); err != nil {
		return errors.Wrap(err, "unmarshal params")
	}

	lock := Lock{
		Params:             lockJSON.Params,
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
