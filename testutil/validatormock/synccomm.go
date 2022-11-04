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

package validatormock

import (
	"context"
	"sync"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/eth2util/signing"
)

type (
	syncDuties     []*eth2v1.SyncCommitteeDuty
	syncSelections []*eth2exp.SyncCommitteeSelection
)

func NewSyncCommMember(eth2Cl eth2wrap.Client, epoch eth2p0.Epoch, signFunc SignFunc, pubkeys []eth2p0.BLSPubKey) *SyncCommMember {
	return &SyncCommMember{
		eth2Cl:       eth2Cl,
		epoch:        epoch,
		pubkeys:      pubkeys,
		signFunc:     signFunc,
		dutiesOK:     make(chan struct{}),
		selections:   make(map[eth2p0.Slot]syncSelections),
		selectionsOK: make(map[eth2p0.Slot]chan struct{}),
	}
}

// SyncCommMember is a stateful structure providing sync committee message and contribution APIs.
type SyncCommMember struct {
	// Immutable state
	eth2Cl   eth2wrap.Client
	epoch    eth2p0.Epoch
	pubkeys  []eth2p0.BLSPubKey
	signFunc SignFunc

	// Mutable state
	mu           sync.Mutex
	vals         validators
	duties       syncDuties
	dutiesOK     chan struct{}
	selections   map[eth2p0.Slot]syncSelections
	selectionsOK map[eth2p0.Slot]chan struct{}
}

func (s *SyncCommMember) Epoch() eth2p0.Epoch {
	return s.epoch
}

func (s *SyncCommMember) setSelections(slot eth2p0.Slot, selections syncSelections) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.selections[slot] = selections

	// Mark selections as done
	ch, ok := s.selectionsOK[slot]
	if !ok {
		ch = make(chan struct{})
		s.selectionsOK[slot] = ch
	}
	close(ch)
}

//nolint:unused
func (s *SyncCommMember) getSelections(slot eth2p0.Slot) syncSelections {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.selections[slot]
}

// getSelectionsOK returns a channel for sync committee selections. When this channel is closed, it means that selections are ready for this slot.
func (s *SyncCommMember) getSelectionsOK(slot eth2p0.Slot) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch, ok := s.selectionsOK[slot]
	if !ok {
		ch = make(chan struct{})
		s.selectionsOK[slot] = ch
	}

	return ch
}

// PrepareEpoch stores sync committee duties and submits sync committee subscriptions at the start of an epoch.
func (s *SyncCommMember) PrepareEpoch(ctx context.Context) error {
	var err error
	s.vals, err = activeValidators(ctx, s.eth2Cl, s.pubkeys)
	if err != nil {
		return err
	}

	s.duties, err = prepareSyncCommDuties(ctx, s.eth2Cl, s.vals, s.epoch)
	if err != nil {
		return err
	}

	err = subscribeSyncCommSubnets(ctx, s.eth2Cl, s.epoch, s.duties)
	if err != nil {
		return err
	}
	close(s.dutiesOK)

	return nil
}

// PrepareSlot prepares selection proofs at the start of a slot.
func (s *SyncCommMember) PrepareSlot(ctx context.Context, slot eth2p0.Slot) error {
	wait(ctx, s.dutiesOK)

	selections, err := prepareSyncSelections(ctx, s.eth2Cl, s.signFunc, s.duties, slot)
	if err != nil {
		return err
	}

	s.setSelections(slot, selections)

	return nil
}

// Message submits sync committee messages at 1/3rd into the slot.
func (s *SyncCommMember) Message(ctx context.Context, slot eth2p0.Slot) error {
	wait(ctx, s.dutiesOK)
	return submitSyncMessage(ctx, s.eth2Cl, slot, s.signFunc, s.duties)
}

// Aggregate submits SignedContributionAndProof at 2/3rd into the slot. It does sync committee aggregations.
// It blocks until sync committee selections are ready for this slot.
func (s *SyncCommMember) Aggregate(ctx context.Context, slot eth2p0.Slot) error {
	wait(ctx, s.dutiesOK, s.getSelectionsOK(slot))
	// TODO(xenowits): Add aggregate function.

	return nil
}

// prepareSyncCommDuties returns sync committee duties for the epoch.
func prepareSyncCommDuties(ctx context.Context, eth2Cl eth2wrap.Client, vals validators, epoch eth2p0.Epoch) (syncDuties, error) {
	if len(vals) == 0 {
		return nil, nil
	}

	var vIdxs []eth2p0.ValidatorIndex
	for idx := range vals {
		vIdxs = append(vIdxs, idx)
	}

	return eth2Cl.SyncCommitteeDuties(ctx, epoch, vIdxs)
}

// subscribeSyncCommSubnets submits sync committee subscriptions at the start of an epoch until next epoch.
func subscribeSyncCommSubnets(ctx context.Context, eth2Cl eth2wrap.Client, epoch eth2p0.Epoch, duties syncDuties) error {
	if len(duties) == 0 {
		return nil
	}

	var subs []*eth2v1.SyncCommitteeSubscription
	for _, duty := range duties {
		subs = append(subs, &eth2v1.SyncCommitteeSubscription{
			ValidatorIndex:       duty.ValidatorIndex,
			SyncCommitteeIndices: duty.ValidatorSyncCommitteeIndices,
			UntilEpoch:           epoch + 1,
		})
	}

	err := eth2Cl.SubmitSyncCommitteeSubscriptions(ctx, subs)
	if err != nil {
		return err
	}

	log.Info(ctx, "Mock sync committee subscription submitted", z.Int("epoch", int(epoch)))

	return nil
}

// prepareSyncSelections returns the sync committee selections for the slot corresponding to the provided validators.
func prepareSyncSelections(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc, duties syncDuties, slot eth2p0.Slot) (syncSelections, error) {
	epoch, err := eth2util.EpochFromSlot(ctx, eth2Cl, slot)
	if err != nil {
		return nil, err
	}

	var selections []*eth2exp.SyncCommitteeSelection
	for _, duty := range duties {
		subcommIdxs, err := getSubcommittees(ctx, eth2Cl, duty)
		if err != nil {
			return nil, err
		}

		for _, subcommIdx := range subcommIdxs {
			data := altair.SyncAggregatorSelectionData{
				Slot:              slot,
				SubcommitteeIndex: uint64(subcommIdx),
			}

			sigRoot, err := data.HashTreeRoot()
			if err != nil {
				return nil, err
			}

			sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainSyncCommitteeSelectionProof, epoch, sigRoot)
			if err != nil {
				return nil, err
			}

			sig, err := signFunc(duty.PubKey, sigData[:])
			if err != nil {
				return nil, err
			}

			selections = append(selections, &eth2exp.SyncCommitteeSelection{
				ValidatorIndex:    duty.ValidatorIndex,
				Slot:              slot,
				SubcommitteeIndex: subcommIdx,
				SelectionProof:    sig,
			})
		}
	}

	return eth2Cl.AggregateSyncCommitteeSelections(ctx, selections)
}

// getSubcommittees returns the subcommittee indexes for the provided sync committee duty.
func getSubcommittees(ctx context.Context, eth2Cl eth2client.SpecProvider, duty *eth2v1.SyncCommitteeDuty) ([]eth2p0.CommitteeIndex, error) {
	spec, err := eth2Cl.Spec(ctx)
	if err != nil {
		return nil, err
	}

	commSize, ok := spec["SYNC_COMMITTEE_SIZE"].(uint64)
	if !ok {
		return nil, errors.New("invalid SYNC_COMMITTEE_SIZE")
	}

	subnetCount, ok := spec["SYNC_COMMITTEE_SUBNET_COUNT"].(uint64)
	if !ok {
		return nil, errors.New("invalid SYNC_COMMITTEE_SUBNET_COUNT")
	}

	var subcommittees []eth2p0.CommitteeIndex
	for _, idx := range duty.ValidatorSyncCommitteeIndices {
		subcommIdx := uint64(idx) / commSize / subnetCount
		subcommittees = append(subcommittees, eth2p0.CommitteeIndex(subcommIdx))
	}

	return subcommittees, nil
}

// submitSyncMessage submits signed sync committee messages for desired slot.
func submitSyncMessage(ctx context.Context, eth2Cl eth2wrap.Client, slot eth2p0.Slot, signFunc SignFunc, duties syncDuties) error {
	if len(duties) == 0 {
		return nil
	}

	blockRoot, err := eth2Cl.BeaconBlockRoot(ctx, "head")
	if err != nil {
		return err
	}

	epoch, err := eth2util.EpochFromSlot(ctx, eth2Cl, slot)
	if err != nil {
		return err
	}

	sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainSyncCommittee, epoch, *blockRoot)
	if err != nil {
		return err
	}

	var msgs []*altair.SyncCommitteeMessage
	for _, duty := range duties {
		sig, err := signFunc(duty.PubKey, sigData[:])
		if err != nil {
			return err
		}

		msgs = append(msgs, &altair.SyncCommitteeMessage{
			Slot:            slot,
			BeaconBlockRoot: *blockRoot,
			ValidatorIndex:  duty.ValidatorIndex,
			Signature:       sig,
		})
	}

	err = eth2Cl.SubmitSyncCommitteeMessages(ctx, msgs)
	if err != nil {
		return err
	}

	log.Info(ctx, "Mock sync committee msg submitted", z.Int("slot", int(slot)))

	return nil
}
