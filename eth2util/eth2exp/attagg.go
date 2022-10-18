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

package eth2exp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
)

// BeaconCommitteeSelectionAggregator is the interface for aggregating beacon committee selection proofs in a DVT cluster.
// TODO(dhruv): Should be removed once it is supported by go-eth2-client.
type BeaconCommitteeSelectionAggregator interface {
	// AggregateBeaconCommitteeSelections returns DVT aggregated beacon committee selection proofs.
	// This would call a new BN API endpoint: POST /eth/v1/aggregate/beacon_committee_selections
	AggregateBeaconCommitteeSelections(ctx context.Context, partialSelections []*BeaconCommitteeSelection) ([]*BeaconCommitteeSelection, error)
}

// BeaconCommitteeSelection is the data required for a beacon committee subscription.
type BeaconCommitteeSelection struct {
	// ValidatorIdex is the index of the validator making the aggregate request.
	ValidatorIndex eth2p0.ValidatorIndex
	// Slot is the slot for which the validator is possibly aggregating.
	Slot eth2p0.Slot
	// SelectionProof is the slot signature required to calculate whether the validator is an aggregator.
	SelectionProof eth2p0.BLSSignature
}

// beaconCommitteeSelectionJSON is the spec representation of the struct.
type beaconCommitteeSelectionJSON struct {
	ValidatorIndex string `json:"validator_index"`
	Slot           string `json:"slot"`
	SelectionProof string `json:"selection_proof"`
}

// MarshalJSON implements json.Marshaler.
func (b *BeaconCommitteeSelection) MarshalJSON() ([]byte, error) {
	resp, err := json.Marshal(&beaconCommitteeSelectionJSON{
		ValidatorIndex: fmt.Sprintf("%d", b.ValidatorIndex),
		Slot:           fmt.Sprintf("%d", b.Slot),
		SelectionProof: fmt.Sprintf("%#x", b.SelectionProof),
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal beacon committee subscription")
	}

	return resp, nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *BeaconCommitteeSelection) UnmarshalJSON(input []byte) error {
	var err error

	var beaconCommitteeSelectionJSON beaconCommitteeSelectionJSON
	if err = json.Unmarshal(input, &beaconCommitteeSelectionJSON); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}
	if beaconCommitteeSelectionJSON.ValidatorIndex == "" {
		return errors.New("validator index missing")
	}
	validatorIndex, err := strconv.ParseUint(beaconCommitteeSelectionJSON.ValidatorIndex, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid value for validator index")
	}
	b.ValidatorIndex = eth2p0.ValidatorIndex(validatorIndex)
	if beaconCommitteeSelectionJSON.Slot == "" {
		return errors.New("slot missing")
	}
	slot, err := strconv.ParseUint(beaconCommitteeSelectionJSON.Slot, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid value for slot")
	}
	b.Slot = eth2p0.Slot(slot)

	if beaconCommitteeSelectionJSON.SelectionProof == "" {
		return errors.New("selection proof missing")
	}

	signature, err := hex.DecodeString(strings.TrimPrefix(beaconCommitteeSelectionJSON.SelectionProof, "0x"))
	if err != nil {
		return errors.Wrap(err, "invalid value for signature")
	}
	if len(signature) != eth2p0.SignatureLength {
		return errors.New("incorrect length for signature")
	}
	copy(b.SelectionProof[:], signature)

	return nil
}

// String returns a string version of the structure.
func (b *BeaconCommitteeSelection) String() (string, error) {
	data, err := json.Marshal(b)
	if err != nil {
		return "", errors.Wrap(err, "marshal BeaconCommitteeSelection")
	}

	return string(data), nil
}
