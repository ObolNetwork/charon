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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/minio/sha256-simd"

	"github.com/obolnetwork/charon/app/errors"
)

type eth2Provider interface {
	eth2client.SpecProvider
}

// BeaconCommitteeSubscriptionsSubmitterV2 is the interface for submitting beacon committee subnet subscription requests.
// TODO(dhruv): Should be removed once it is supported by go-eth2-client.
type BeaconCommitteeSubscriptionsSubmitterV2 interface {
	// SubmitBeaconCommitteeSubscriptionsV2 subscribes to beacon committees.
	// This would call a new BN API endpoint: POST /eth/v1/aggregate/beacon_committee_selections
	SubmitBeaconCommitteeSubscriptionsV2(ctx context.Context, subscriptions []*BeaconCommitteeSubscription) ([]*BeaconCommitteeSubscriptionResponse, error)
}

// BeaconCommitteeSubscription is the data required for a beacon committee subscription.
type BeaconCommitteeSubscription struct {
	// ValidatorIdex is the index of the validator making the subscription request.
	ValidatorIndex eth2p0.ValidatorIndex
	// Slot is the slot for which the validator is attesting.
	Slot eth2p0.Slot
	// CommitteeIndex is the index of the committee of which the validator is a member at the given slot.
	CommitteeIndex eth2p0.CommitteeIndex
	// CommitteesAtSlot is the number of committees at the given slot.
	CommitteesAtSlot uint64
	// SlotSignature is the slot signature required to calculate whether the validator is an aggregator.
	SlotSignature eth2p0.BLSSignature
}

// beaconCommitteeSubscriptionJSON is the spec representation of the struct.
type beaconCommitteeSubscriptionJSON struct {
	ValidatorIndex   string `json:"validator_index"`
	Slot             string `json:"slot"`
	CommitteeIndex   string `json:"committee_index"`
	CommitteesAtSlot string `json:"committees_at_slot"`
	SlotSignature    string `json:"slot_signature"`
}

// MarshalJSON implements json.Marshaler.
func (b *BeaconCommitteeSubscription) MarshalJSON() ([]byte, error) {
	resp, err := json.Marshal(&beaconCommitteeSubscriptionJSON{
		ValidatorIndex:   fmt.Sprintf("%d", b.ValidatorIndex),
		Slot:             fmt.Sprintf("%d", b.Slot),
		CommitteeIndex:   fmt.Sprintf("%d", b.CommitteeIndex),
		CommitteesAtSlot: fmt.Sprintf("%d", b.CommitteesAtSlot),
		SlotSignature:    fmt.Sprintf("%#x", b.SlotSignature),
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal beacon committee subscriptions v2")
	}

	return resp, nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *BeaconCommitteeSubscription) UnmarshalJSON(input []byte) error {
	var err error

	var beaconCommitteeSubscriptionJSON beaconCommitteeSubscriptionJSON
	if err = json.Unmarshal(input, &beaconCommitteeSubscriptionJSON); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}
	if beaconCommitteeSubscriptionJSON.ValidatorIndex == "" {
		return errors.New("validator index missing")
	}
	validatorIndex, err := strconv.ParseUint(beaconCommitteeSubscriptionJSON.ValidatorIndex, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid value for validator index")
	}
	b.ValidatorIndex = eth2p0.ValidatorIndex(validatorIndex)
	if beaconCommitteeSubscriptionJSON.Slot == "" {
		return errors.New("slot missing")
	}
	slot, err := strconv.ParseUint(beaconCommitteeSubscriptionJSON.Slot, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid value for slot")
	}
	b.Slot = eth2p0.Slot(slot)
	if beaconCommitteeSubscriptionJSON.CommitteeIndex == "" {
		return errors.New("committee index missing")
	}
	committeeIndex, err := strconv.ParseUint(beaconCommitteeSubscriptionJSON.CommitteeIndex, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid value for committee index")
	}
	b.CommitteeIndex = eth2p0.CommitteeIndex(committeeIndex)
	if beaconCommitteeSubscriptionJSON.CommitteesAtSlot == "" {
		return errors.New("committees at slot missing")
	}
	if b.CommitteesAtSlot, err = strconv.ParseUint(beaconCommitteeSubscriptionJSON.CommitteesAtSlot, 10, 64); err != nil {
		return errors.Wrap(err, "invalid value for committees at slot")
	}
	if b.CommitteesAtSlot == 0 {
		return errors.New("committees at slot cannot be 0")
	}

	if beaconCommitteeSubscriptionJSON.SlotSignature == "" {
		return errors.New("slot signature missing")
	}

	signature, err := hex.DecodeString(strings.TrimPrefix(beaconCommitteeSubscriptionJSON.SlotSignature, "0x"))
	if err != nil {
		return errors.Wrap(err, "invalid value for signature")
	}
	if len(signature) != eth2p0.SignatureLength {
		return errors.New("incorrect length for signature")
	}
	copy(b.SlotSignature[:], signature)

	return nil
}

// String returns a string version of the structure.
func (b *BeaconCommitteeSubscription) String() (string, error) {
	data, err := json.Marshal(b)
	if err != nil {
		return "", errors.Wrap(err, "marshal BeaconCommitteeSubscription")
	}

	return string(data), nil
}

// BeaconCommitteeSubscriptionResponse is the response from beacon node after submitting BeaconCommitteeSubscription.
type BeaconCommitteeSubscriptionResponse struct {
	// ValidatorIndex is the index of the validator the made the subscription request.
	ValidatorIndex eth2p0.ValidatorIndex
	// Slot is the slot for which the validator is attesting.
	Slot eth2p0.Slot
	// CommitteeIndex is the index of the committee of which the validator is a member at the given slot.
	CommitteeIndex eth2p0.CommitteeIndex
	// CommitteesAtSlot is the number of committees at the given slot.
	CommitteesAtSlot uint64
	// IsAggregator indicates whether the validator is an attestation aggregator.
	IsAggregator bool
	// SelectionProof is the slot signature proving the validator is an aggregator for this slot and committee.
	SelectionProof eth2p0.BLSSignature
}

// CalculateCommitteeSubscriptionResponse returns a BeaconCommitteeSubscriptionResponse with isAggregator field set to true if the validator is an aggregator.
func CalculateCommitteeSubscriptionResponse(ctx context.Context, eth2Cl eth2Provider, sub *BeaconCommitteeSubscription,
	committeeLength uint64,
) (*BeaconCommitteeSubscriptionResponse, error) {
	isAgg, err := isAggregator(ctx, eth2Cl, committeeLength, sub.SlotSignature)
	if err != nil {
		return nil, err
	}

	return &BeaconCommitteeSubscriptionResponse{
		ValidatorIndex:   sub.ValidatorIndex,
		Slot:             sub.Slot,
		CommitteeIndex:   sub.CommitteeIndex,
		CommitteesAtSlot: sub.CommitteesAtSlot,
		SelectionProof:   sub.SlotSignature,
		IsAggregator:     isAgg,
	}, nil
}

// isAggregator returns true if the validator is the attestation aggregator for the given committee.
// Refer: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#aggregation-selection
func isAggregator(ctx context.Context, eth2Cl eth2Provider, commLen uint64, slotSig eth2p0.BLSSignature) (bool, error) {
	spec, err := eth2Cl.Spec(ctx)
	if err != nil {
		return false, errors.Wrap(err, "get eth2 spec")
	}

	aggsPerComm, ok := spec["TARGET_AGGREGATORS_PER_COMMITTEE"].(uint64)
	if !ok {
		return false, errors.New("invalid TARGET_AGGREGATORS_PER_COMMITTEE")
	}

	modulo := commLen / aggsPerComm
	if modulo < 1 {
		modulo = 1
	}

	h := sha256.New()
	_, err = h.Write(slotSig[:])
	if err != nil {
		return false, errors.Wrap(err, "calculate sha256")
	}

	hash := h.Sum(nil)
	lowest8bytes := hash[0:8]
	asUint64 := binary.LittleEndian.Uint64(lowest8bytes)

	return asUint64%modulo == 0, nil
}
