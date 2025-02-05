// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package statecomm

import (
	"encoding/json"
	"fmt"
	"strconv"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
)

// StateCommitteesResponse is simplified response structure for fetching the beacon node committees for a given state.
// This is the response from the BN API endpoint: /eth/v1/beacon/states/{state_id}/validators.
type StateCommitteesResponse struct {
	Data []*StateCommittee `json:"data"`
}

// StateCommittee is the Data field from the BN API endpoint /eth/v1/beacon/states/{state_id}/validators response.
type StateCommittee struct {
	Index      eth2p0.CommitteeIndex   `json:"index"`
	Slot       eth2p0.Slot             `json:"slot"`
	Validators []eth2p0.ValidatorIndex `json:"validators"`
}

// beaconCommitteeSelectionJSON is the spec representation of the struct.
type stateCommitteeJSON struct {
	Index      string   `json:"index"`
	Slot       string   `json:"slot"`
	Validators []string `json:"validators"`
}

// MarshalJSON implements json.Marshaler.
func (b *StateCommittee) MarshalJSON() ([]byte, error) {
	var validators []string
	for _, v := range b.Validators {
		validators = append(validators, fmt.Sprintf("%d", v))
	}

	resp, err := json.Marshal(&stateCommitteeJSON{
		Index:      fmt.Sprintf("%d", b.Index),
		Slot:       fmt.Sprintf("%d", b.Slot),
		Validators: validators,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal state committee subscription")
	}

	return resp, nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *StateCommittee) UnmarshalJSON(input []byte) error {
	var err error

	var stateCommitteeJSON stateCommitteeJSON
	if err = json.Unmarshal(input, &stateCommitteeJSON); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}

	if stateCommitteeJSON.Index == "" {
		return errors.New("index missing")
	}
	index, err := strconv.ParseUint(stateCommitteeJSON.Index, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid value for index")
	}
	b.Index = eth2p0.CommitteeIndex(index)

	if stateCommitteeJSON.Slot == "" {
		return errors.New("slot missing")
	}
	slot, err := strconv.ParseUint(stateCommitteeJSON.Slot, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid value for slot")
	}
	b.Slot = eth2p0.Slot(slot)

	var validators []eth2p0.ValidatorIndex
	for _, v := range stateCommitteeJSON.Validators {
		validator, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return errors.Wrap(err, "invalid value for validator")
		}
		validators = append(validators, eth2p0.ValidatorIndex(validator))
	}
	b.Validators = validators

	return nil
}

// String returns a string version of the structure.
func (b *StateCommittee) String() (string, error) {
	data, err := json.Marshal(b)
	if err != nil {
		return "", errors.Wrap(err, "marshal StateCommittee")
	}

	return string(data), nil
}
