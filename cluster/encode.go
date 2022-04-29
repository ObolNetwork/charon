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
)

// defFmt is the json formatter of Definition.
type defFmt struct {
	Name                string     `json:"name,omitempty"`
	Operators           []Operator `json:"operators"`
	UUID                string     `json:"uuid"`
	Version             string     `json:"version"`
	NumValidators       int        `json:"num_validators"`
	Threshold           int        `json:"threshold"`
	FeeRecipientAddress string     `json:"fee_recipient_address,omitempty"`
	WithdrawalAddress   string     `json:"withdrawal_address,omitempty"`
	DKGAlgorithm        string     `json:"dkg_algorithm"`
	ForkVersion         string     `json:"fork_version"`
	DefinitionHash      []byte     `json:"definition_hash"`
	OperatorSignatures  [][]byte   `json:"operator_signatures"`
}

func (d Definition) MarshalJSON() ([]byte, error) {
	// Marshal definition hash
	hash, err := d.HashTreeRoot()
	if err != nil {
		return nil, errors.Wrap(err, "hash lock")
	}

	// Marshal json version of lock
	resp, err := json.Marshal(defFmt{
		Name:                d.Name,
		UUID:                d.UUID,
		Version:             d.Version,
		NumValidators:       d.NumValidators,
		Threshold:           d.Threshold,
		FeeRecipientAddress: d.FeeRecipientAddress,
		WithdrawalAddress:   d.WithdrawalAddress,
		DKGAlgorithm:        d.DKGAlgorithm,
		ForkVersion:         d.ForkVersion,
		Operators:           d.Operators,
		OperatorSignatures:  d.OperatorSignatures,
		DefinitionHash:      hash[:],
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal lock")
	}

	return resp, nil
}

func (d *Definition) UnmarshalJSON(data []byte) error {
	// Get the version directly
	version := struct {
		Version string `json:"version"`
	}{}
	if err := json.Unmarshal(data, &version); err != nil {
		return errors.Wrap(err, "unmarshal version")
	} else if version.Version != definitionVersion {
		return errors.Wrap(err, "invalid definition version")
	}

	var defFmt defFmt
	if err := json.Unmarshal(data, &defFmt); err != nil {
		return errors.Wrap(err, "unmarshal definition")
	}

	def := Definition{
		Name:                defFmt.Name,
		UUID:                defFmt.UUID,
		Version:             defFmt.Version,
		NumValidators:       defFmt.NumValidators,
		Threshold:           defFmt.Threshold,
		FeeRecipientAddress: defFmt.FeeRecipientAddress,
		WithdrawalAddress:   defFmt.WithdrawalAddress,
		DKGAlgorithm:        defFmt.DKGAlgorithm,
		ForkVersion:         defFmt.ForkVersion,
		Operators:           defFmt.Operators,
		OperatorSignatures:  defFmt.OperatorSignatures,
	}

	hash, err := def.HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "hash lock")
	}

	if !bytes.Equal(defFmt.DefinitionHash, hash[:]) {
		return errors.New("invalid definition hash")
	}

	*d = def

	return nil
}

// lockFmt is the json formatter of Lock.
type lockFmt struct {
	Definition         Definition      `json:"cluster_definition"`
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
