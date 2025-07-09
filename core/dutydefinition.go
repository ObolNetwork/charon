// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"

	"github.com/obolnetwork/charon/app/errors"
)

var (
	_ DutyDefinition = AttesterDefinition{}
	_ DutyDefinition = ProposerDefinition{}
	_ DutyDefinition = SyncCommitteeDefinition{}
)

// NewAttesterDefinition is a convenience function that returns a new attester definition.
func NewAttesterDefinition(duty *eth2v1.AttesterDuty) AttesterDefinition {
	return AttesterDefinition{AttesterDuty: *duty}
}

// AttesterDefinition defines an attester duty. It implements DutyDefinition.
// Note the slight rename from Duty to Definition to avoid overloading the term Duty.
type AttesterDefinition struct {
	eth2v1.AttesterDuty
}

func (d AttesterDefinition) Clone() (DutyDefinition, error) {
	duty := new(eth2v1.AttesterDuty)

	err := cloneJSONMarshaler(&d.AttesterDuty, duty)
	if err != nil {
		return nil, errors.Wrap(err, "clone attester definition")
	}

	return NewAttesterDefinition(duty), nil
}

func (d AttesterDefinition) MarshalJSON() ([]byte, error) {
	return d.AttesterDuty.MarshalJSON()
}

// NewProposerDefinition is a convenience function that returns a new proposer definition.
func NewProposerDefinition(duty *eth2v1.ProposerDuty) ProposerDefinition {
	return ProposerDefinition{ProposerDuty: *duty}
}

// ProposerDefinition defines a block proposer duty. It implements DutyDefinition.
// Note the slight rename from Duty to Definition to avoid overloading the term Duty.
type ProposerDefinition struct {
	eth2v1.ProposerDuty
}

func (d ProposerDefinition) Clone() (DutyDefinition, error) {
	duty := new(eth2v1.ProposerDuty)

	err := cloneJSONMarshaler(&d.ProposerDuty, duty)
	if err != nil {
		return nil, errors.Wrap(err, "clone proposer definition")
	}

	return NewProposerDefinition(duty), nil
}

func (d ProposerDefinition) MarshalJSON() ([]byte, error) {
	return d.ProposerDuty.MarshalJSON()
}

// NewSyncCommitteeDefinition is a convenience function that returns a new SyncCommitteeDefinition.
func NewSyncCommitteeDefinition(duty *eth2v1.SyncCommitteeDuty) DutyDefinition {
	return SyncCommitteeDefinition{SyncCommitteeDuty: *duty}
}

// SyncCommitteeDefinition defines a sync committee duty. It implements DutyDefinition.
// Note the slight rename from Duty to Definition to avoid overloading the term Duty.
type SyncCommitteeDefinition struct {
	eth2v1.SyncCommitteeDuty
}

func (s SyncCommitteeDefinition) Clone() (DutyDefinition, error) {
	duty := new(eth2v1.SyncCommitteeDuty)

	err := cloneJSONMarshaler(&s.SyncCommitteeDuty, duty)
	if err != nil {
		return nil, errors.Wrap(err, "clone sync committee definition")
	}

	return NewSyncCommitteeDefinition(duty), nil
}

func (s SyncCommitteeDefinition) MarshalJSON() ([]byte, error) {
	return s.SyncCommitteeDuty.MarshalJSON()
}
