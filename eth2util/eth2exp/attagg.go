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
	"strings"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/minio/sha256-simd"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

type eth2Provider interface {
	eth2client.BeaconCommitteesProvider
	eth2client.SlotsPerEpochProvider
	eth2client.SpecProvider
}

// BeaconCommitteeSubscriptionsSubmitterV2 is the interface for submitting beacon committee subnet subscription requests.
// It supports DVT middleware by returning cluster updated subscription values or the same values if no DVT middleware.
// TODO(dhruv): Should be removed once it is supported by go-eth2-client.
type BeaconCommitteeSubscriptionsSubmitterV2 interface {
	// SubmitBeaconCommitteeSubscriptionsV2 subscribes to beacon committees and returns the same or possible DVT updated values.
	SubmitBeaconCommitteeSubscriptionsV2(context.Context, []*BeaconCommitteeSubscription) ([]*BeaconCommitteeSubscription, error)
}

// BeaconCommitteeSubscription is the data required for (and returned from) a beacon committee subscription.
type BeaconCommitteeSubscription struct {
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

// beaconCommitteeSubscriptionJSON is the spec representation of the struct.
type beaconCommitteeSubscriptionJSON struct {
	ValidatorIndex   uint64 `json:"validator_index,string"`
	Slot             uint64 `json:"slot,string"`
	CommitteeIndex   uint64 `json:"committee_index,string"`
	CommitteesAtSlot uint64 `json:"committees_at_slot,string"`
	SelectionProof   string `json:"selection_proof"`
	IsAggregator     bool   `json:"is_aggregator"`
}

// MarshalJSON implements json.Marshaler.
func (b *BeaconCommitteeSubscription) MarshalJSON() ([]byte, error) {
	resp, err := json.Marshal(&beaconCommitteeSubscriptionJSON{
		ValidatorIndex:   uint64(b.ValidatorIndex),
		Slot:             uint64(b.Slot),
		CommitteeIndex:   uint64(b.CommitteeIndex),
		CommitteesAtSlot: b.CommitteesAtSlot,
		SelectionProof:   fmt.Sprintf("%#x", b.SelectionProof),
		IsAggregator:     b.IsAggregator,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal beacon committee subscriptions v2")
	}

	return resp, nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *BeaconCommitteeSubscription) UnmarshalJSON(input []byte) error {
	var err error

	var subJSON beaconCommitteeSubscriptionJSON
	if err = json.Unmarshal(input, &subJSON); err != nil {
		return errors.Wrap(err, "unmarshal json")
	}

	b.Slot = eth2p0.Slot(subJSON.Slot)
	b.ValidatorIndex = eth2p0.ValidatorIndex(subJSON.ValidatorIndex)
	b.CommitteeIndex = eth2p0.CommitteeIndex(subJSON.CommitteeIndex)
	b.CommitteesAtSlot = subJSON.CommitteesAtSlot
	b.IsAggregator = subJSON.IsAggregator

	signature, err := hex.DecodeString(strings.TrimPrefix(subJSON.SelectionProof, "0x"))
	if err != nil {
		return errors.Wrap(err, "invalid value for signature")
	} else if len(signature) != eth2p0.SignatureLength {
		return errors.New("incorrect length for signature")
	}
	copy(b.SelectionProof[:], signature)

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

// CalculateCommitteeSubscription returns a copy of the BeaconCommitteeSubscription with IsAggregator
// field populated according to the SelectionProof.
func CalculateCommitteeSubscription(ctx context.Context, eth2Cl eth2Provider, sub *BeaconCommitteeSubscription) (*BeaconCommitteeSubscription, error) {
	isAgg, err := IsAttestationAggregator(ctx, eth2Cl, sub.Slot, sub.CommitteeIndex, sub.SelectionProof)
	if err != nil {
		return nil, err
	}

	return &BeaconCommitteeSubscription{
		ValidatorIndex:   sub.ValidatorIndex,
		Slot:             sub.Slot,
		CommitteeIndex:   sub.CommitteeIndex,
		CommitteesAtSlot: sub.CommitteesAtSlot,
		SelectionProof:   sub.SelectionProof,
		IsAggregator:     isAgg,
	}, nil
}

// IsAttestationAggregator returns true if in the slot signature proves an attestation aggregator.
func IsAttestationAggregator(ctx context.Context, eth2Cl eth2Provider, slot eth2p0.Slot,
	committeeIndex eth2p0.CommitteeIndex, slotSig eth2p0.BLSSignature,
) (bool, error) {
	committeeLen, err := getCommitteeLength(ctx, eth2Cl, committeeIndex, slot)
	if err != nil {
		return false, err
	}

	return isAggregator(ctx, eth2Cl, uint64(committeeLen), slotSig)
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

// getCommitteeLength returns the number of validators in the input committee at the given slot.
func getCommitteeLength(ctx context.Context, eth2Cl eth2Provider, commIdx eth2p0.CommitteeIndex, slot eth2p0.Slot) (int, error) {
	epoch, err := epochFromSlot(ctx, eth2Cl, slot)
	if err != nil {
		return 0, err
	}

	comms, err := eth2Cl.BeaconCommitteesAtEpoch(ctx, "head", epoch)
	if err != nil {
		return 0, errors.Wrap(err, "get beacon committees at epoch")
	}

	for _, d := range comms {
		if d.Index == commIdx {
			return len(d.Validators), nil
		}
	}

	return 0, errors.New("committee not found", z.I64("slot", int64(slot)), z.I64("committee_index", int64(commIdx)))
}

// epochFromSlot returns the epoch corresponding to the input slot.
func epochFromSlot(ctx context.Context, eth2Cl eth2Provider, slot eth2p0.Slot) (eth2p0.Epoch, error) {
	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return 0, errors.Wrap(err, "get slots per epoch")
	}

	return eth2p0.Epoch(uint64(slot) / slotsPerEpoch), nil
}
