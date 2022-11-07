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
		blockRoot:    make(map[eth2p0.Slot]eth2p0.Root),
		blockRootOK:  make(map[eth2p0.Slot]chan struct{}),
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
	vals         validators // Current set of active validators
	duties       syncDuties // Sync committee duties
	dutiesOK     chan struct{}
	selections   map[eth2p0.Slot]syncSelections // Sync committee selections per slot
	selectionsOK map[eth2p0.Slot]chan struct{}
	blockRoot    map[eth2p0.Slot]eth2p0.Root // Beacon block root per slot
	blockRootOK  map[eth2p0.Slot]chan struct{}
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

// getSelections returns the sync committee selections for the provided slot.
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

// setBlockRoot sets block root for the slot.
func (s *SyncCommMember) setBlockRoot(slot eth2p0.Slot, blockRoot eth2p0.Root) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.blockRoot[slot] = blockRoot

	// Mark block root assigned for the slot
	ch, ok := s.blockRootOK[slot]
	if !ok {
		ch = make(chan struct{})
		s.blockRootOK[slot] = ch
	}

	close(ch)
}

// getBlockRoot returns the beacon block root for the provided slot.
func (s *SyncCommMember) getBlockRoot(slot eth2p0.Slot) eth2p0.Root {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.blockRoot[slot]
}

// getBlockRootOK returns a channel for beacon block root. When this channel is closed, it means that block root is ready for this slot.
func (s *SyncCommMember) getBlockRootOK(slot eth2p0.Slot) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch, ok := s.blockRootOK[slot]
	if !ok {
		ch = make(chan struct{})
		s.blockRootOK[slot] = ch
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

// Message submits sync committee messages at 1/3rd into the slot. It also sets the beacon block root for the slot.
func (s *SyncCommMember) Message(ctx context.Context, slot eth2p0.Slot) error {
	wait(ctx, s.dutiesOK)

	blockRoot, err := s.eth2Cl.BeaconBlockRoot(ctx, "head")
	if err != nil {
		return err
	}

	err = submitSyncMessages(ctx, s.eth2Cl, slot, *blockRoot, s.signFunc, s.duties)
	if err != nil {
		return err
	}

	s.setBlockRoot(slot, *blockRoot)

	return nil
}

// Aggregate submits SignedContributionAndProof at 2/3rd into the slot. It does sync committee aggregations.
// It blocks until sync committee selections are ready for this slot.
func (s *SyncCommMember) Aggregate(ctx context.Context, slot eth2p0.Slot) (bool, error) {
	wait(ctx, s.dutiesOK, s.getSelectionsOK(slot), s.getBlockRootOK(slot))

	return aggContributions(ctx, s.eth2Cl, s.signFunc, slot, s.vals, s.getSelections(slot), s.getBlockRoot(slot))
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

// prepareSyncSelections returns the aggregate sync committee selections for the slot corresponding to the provided validators.
func prepareSyncSelections(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc, duties syncDuties, slot eth2p0.Slot) (syncSelections, error) {
	epoch, err := eth2util.EpochFromSlot(ctx, eth2Cl, slot)
	if err != nil {
		return nil, err
	}

	var partials []*eth2exp.SyncCommitteeSelection
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

			partials = append(partials, &eth2exp.SyncCommitteeSelection{
				ValidatorIndex:    duty.ValidatorIndex,
				Slot:              slot,
				SubcommitteeIndex: subcommIdx,
				SelectionProof:    sig,
			})
		}
	}

	aggregateSelections, err := eth2Cl.AggregateSyncCommitteeSelections(ctx, partials)
	if err != nil {
		return nil, err
	}

	var selections syncSelections
	for _, selection := range aggregateSelections {
		// Check if the validator is an aggregator.
		ok, err := eth2exp.IsSyncCommAggregator(ctx, eth2Cl, selection.SelectionProof)
		if err != nil {
			return nil, err
		} else if !ok {
			continue
		}

		selections = append(selections, selection)
	}

	log.Info(ctx, "Resolved sync committee aggregators", z.Int("aggregators", len(selections)))

	return selections, nil
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

// submitSyncMessages submits signed sync committee messages for desired slot.
func submitSyncMessages(ctx context.Context, eth2Cl eth2wrap.Client, slot eth2p0.Slot, blockRoot eth2p0.Root, signFunc SignFunc, duties syncDuties) error {
	if len(duties) == 0 {
		return nil
	}

	epoch, err := eth2util.EpochFromSlot(ctx, eth2Cl, slot)
	if err != nil {
		return err
	}

	sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainSyncCommittee, epoch, blockRoot)
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
			BeaconBlockRoot: blockRoot,
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

// aggContributions submits aggregate altair.SignedContributionAndProof. It returns false if contribution aggregation is not required.
func aggContributions(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc, slot eth2p0.Slot, vals validators,
	selections syncSelections, blockRoot eth2p0.Root,
) (bool, error) {
	if len(selections) == 0 {
		return false, nil
	}

	epoch, err := eth2util.EpochFromSlot(ctx, eth2Cl, slot)
	if err != nil {
		return false, err
	}

	var signedContribAndProofs []*altair.SignedContributionAndProof
	for _, selection := range selections {
		// Query BN to get sync committee contribution.
		contrib, err := eth2Cl.SyncCommitteeContribution(ctx, selection.Slot, uint64(selection.SubcommitteeIndex), blockRoot)
		if err != nil {
			return false, err
		}

		vIdx := selection.ValidatorIndex
		contribAndProof := &altair.ContributionAndProof{
			AggregatorIndex: vIdx,
			Contribution:    contrib,
			SelectionProof:  selection.SelectionProof,
		}

		val, ok := vals[vIdx]
		if !ok {
			return false, errors.New("missing validator index", z.U64("vidx", uint64(vIdx)))
		}

		proofRoot, err := contribAndProof.HashTreeRoot()
		if err != nil {
			return false, err
		}

		sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainContributionAndProof, epoch, proofRoot)
		if err != nil {
			return false, err
		}

		sig, err := signFunc(val.Validator.PublicKey, sigData[:])
		if err != nil {
			return false, err
		}

		signedContribAndProof := &altair.SignedContributionAndProof{
			Message:   contribAndProof,
			Signature: sig,
		}

		signedContribAndProofs = append(signedContribAndProofs, signedContribAndProof)
	}

	if err := eth2Cl.SubmitSyncCommitteeContributions(ctx, signedContribAndProofs); err != nil {
		return false, err
	}

	return true, nil
}
