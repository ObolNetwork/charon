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
	"github.com/obolnetwork/charon/app/z"
)

// SyncCommitteeSelectionAggregator is the interface for aggregating sync committee selection proofs.
type SyncCommitteeSelectionAggregator interface {
	// AggregateSyncCommitteeSelections returns the threshold aggregated sync committee selection proofs.
	// This would call a new BN API endpoint: POST /eth/v1/validator/sync_committee_selections
	AggregateSyncCommitteeSelections(ctx context.Context, partialSelections []*SyncCommitteeSelection) ([]*SyncCommitteeSelection, error)
}

// SyncCommitteeSelection is the data required for a sync committee subscription.
type SyncCommitteeSelection struct {
	// ValidatorIndex is the index of the validator making the selection request.
	ValidatorIndex eth2p0.ValidatorIndex
	// Slot is the slot for which the selection request is made.
	Slot eth2p0.Slot
	// SubcommitteeIndex is the subcommittee to which the validator is assigned.
	SubcommitteeIndex eth2p0.CommitteeIndex
	// SelectionProof is a partial or an aggregated signature.
	SelectionProof eth2p0.BLSSignature
}

// syncCommitteeSelectionJSON is the spec representation of the struct.
type syncCommitteeSelectionJSON struct {
	ValidatorIndex    string `json:"validator_index"`
	Slot              string `json:"slot"`
	SubcommitteeIndex string `json:"subcommittee_index"`
	SelectionProof    string `json:"selection_proof"`
}

// MarshalJSON implements json.Marshaler.
func (s *SyncCommitteeSelection) MarshalJSON() ([]byte, error) {
	resp, err := json.Marshal(&syncCommitteeSelectionJSON{
		ValidatorIndex:    fmt.Sprintf("%d", s.ValidatorIndex),
		Slot:              fmt.Sprintf("%d", s.Slot),
		SubcommitteeIndex: fmt.Sprintf("%d", s.SubcommitteeIndex),
		SelectionProof:    fmt.Sprintf("%#x", s.SelectionProof),
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal sync committee selection")
	}

	return resp, nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *SyncCommitteeSelection) UnmarshalJSON(input []byte) error {
	var err error

	var syncCommitteeSelectionJSON syncCommitteeSelectionJSON
	if err = json.Unmarshal(input, &syncCommitteeSelectionJSON); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}

	// verify and unmarshal ValidatorIndex.
	if syncCommitteeSelectionJSON.ValidatorIndex == "" {
		return errors.New("validator index missing")
	}
	validatorIndex, err := strconv.ParseUint(syncCommitteeSelectionJSON.ValidatorIndex, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid value for validator index", z.Str("vIdx", syncCommitteeSelectionJSON.ValidatorIndex))
	}
	s.ValidatorIndex = eth2p0.ValidatorIndex(validatorIndex)

	// verify and unmarshal Slot.
	if syncCommitteeSelectionJSON.Slot == "" {
		return errors.New("slot missing")
	}
	slot, err := strconv.ParseUint(syncCommitteeSelectionJSON.Slot, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid value for slot", z.Str("slot", syncCommitteeSelectionJSON.Slot))
	}
	s.Slot = eth2p0.Slot(slot)

	// verify and unmarshal SubcommitteeIndex.
	if syncCommitteeSelectionJSON.SubcommitteeIndex == "" {
		return errors.New("subcommittee index missing")
	}
	subcommIdx, err := strconv.ParseUint(syncCommitteeSelectionJSON.SubcommitteeIndex, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid value for subcommittee index", z.Str("subcommIdx", syncCommitteeSelectionJSON.SubcommitteeIndex))
	}
	s.SubcommitteeIndex = eth2p0.CommitteeIndex(subcommIdx)

	// verify and unmarshal SelectionProof.
	if syncCommitteeSelectionJSON.SelectionProof == "" {
		return errors.New("selection proof missing")
	}
	signature, err := hex.DecodeString(strings.TrimPrefix(syncCommitteeSelectionJSON.SelectionProof, "0x"))
	if err != nil {
		return errors.Wrap(err, "invalid value for signature", z.Str("sig", syncCommitteeSelectionJSON.SelectionProof))
	}
	if len(signature) != eth2p0.SignatureLength {
		return errors.New("invalid signature length")
	}
	copy(s.SelectionProof[:], signature)

	return nil
}

// String returns a string version of SyncCommitteeSelection.
func (s *SyncCommitteeSelection) String() (string, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return "", errors.Wrap(err, "marshal SyncCommitteeSelection")
	}

	return string(data), nil
}
