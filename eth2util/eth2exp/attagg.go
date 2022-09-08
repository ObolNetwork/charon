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
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/eth2util"
)

// targetAggregatorsPerCommittee defines the number of aggregators inside one committee. https://github.com/ethereum/consensus-specs/blob/0ba5b3b5c5bb58fbe0f094dcd02dedc4ff1c6f7c/specs/phase0/validator.md#misc
const targetAggregatorsPerCommittee = 16

// getCommitteesResponse is the HTTP response for /eth/v1/beacon/states/{state_id}/committees (https://ethereum.github.io/beacon-APIs/#/Beacon/getEpochCommittees).
type getCommitteesResponse struct {
	Data []struct {
		Index      int   `json:"index"`
		Validators []int `json:"validators"`
	} `json:"data"`
}

// BeaconCommitteeSubscriptionsSubmitterV2 is the interface for submitting beacon committee subnet subscription requests.
// TODO(dhruv): Should be removed once it is supported by go-eth2-client.
type BeaconCommitteeSubscriptionsSubmitterV2 interface {
	// SubmitBeaconCommitteeSubscriptionsV2 subscribes to beacon committees.
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
	// ValidatorIndex is the index of the validator that made the subscription request.
	ValidatorIndex eth2p0.ValidatorIndex
	// IsAggregator indicates whether the validator is an attestation aggregator.
	IsAggregator bool
}

// CalculateCommitteeSubscriptionResponse returns a BeaconCommitteeSubscriptionResponse with IsAggregator field set to true if the validator is an aggregator.
func CalculateCommitteeSubscriptionResponse(ctx context.Context, beaconNode string, subscription BeaconCommitteeSubscription) (BeaconCommitteeSubscriptionResponse, error) {
	committeeLen, err := getCommitteeLength(ctx, beaconNode, subscription.CommitteeIndex, subscription.Slot)
	if err != nil {
		return BeaconCommitteeSubscriptionResponse{}, err
	}

	return BeaconCommitteeSubscriptionResponse{
		ValidatorIndex: subscription.ValidatorIndex,
		IsAggregator:   isAggregator(uint64(committeeLen), subscription.SlotSignature),
	}, nil
}

// isAggregator returns true if the signature is from the input validator. https://github.com/ethereum/consensus-specs/blob/0ba5b3b5c5bb58fbe0f094dcd02dedc4ff1c6f7c/specs/phase0/validator.md#aggregation-selection
func isAggregator(committeeLen uint64, slotSig eth2p0.BLSSignature) bool {
	modulo := uint64(1)

	if committeeLen/targetAggregatorsPerCommittee > 1 {
		modulo = committeeLen / targetAggregatorsPerCommittee
	}

	b := eth2util.SHA256(slotSig[:])

	return binary.LittleEndian.Uint64(b[:8])%modulo == 0
}

// getCommitteeLength calls the beacon node endpoint '/eth/v1/beacon/states/{state_id}/committees' and returns the number of validators in the input committee at the given slot.
func getCommitteeLength(ctx context.Context, beaconNode string, commIdx eth2p0.CommitteeIndex, slot eth2p0.Slot) (int, error) {
	u, err := url.Parse(beaconNode)
	if err != nil {
		return 0, errors.Wrap(err, "invalid beacon node endpoint")
	}

	stateID := "head" // canonical head in beacon node's view
	u = u.JoinPath(fmt.Sprintf("/eth/v1/beacon/states/%s/committees", stateID))

	q := u.Query()
	q.Set("index", strconv.Itoa(int(commIdx)))
	q.Set("slot", strconv.Itoa(int(slot)))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, errors.Wrap(err, "create http request")
	}

	resp, err := new(http.Client).Do(req)
	if err != nil {
		return 0, errors.Wrap(err, "fetch committee subscription")
	}
	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, errors.Wrap(err, "read response body")
	}

	var res getCommitteesResponse
	if err := json.Unmarshal(buf, &res); err != nil {
		return 0, errors.Wrap(err, "unmarshal get committee response")
	}

	committeeLen := -1
	for _, d := range res.Data {
		if eth2p0.CommitteeIndex(d.Index) == commIdx {
			committeeLen = len(d.Validators)
		}
	}
	if committeeLen == -1 {
		return 0, errors.New("committee index absent in beacon node response")
	}

	return committeeLen, nil
}
