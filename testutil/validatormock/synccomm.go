// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatormock

import (
	"context"
	"sync"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2api "github.com/attestantio/go-eth2-client/api"
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
	resp := &SyncCommMember{
		eth2Cl:   eth2Cl,
		epoch:    epoch,
		pubkeys:  pubkeys,
		signFunc: signFunc,
		dutiesOK: make(chan struct{}),
	}

	resp.mutable.selections = make(map[eth2p0.Slot]syncSelections)
	resp.mutable.selectionsOK = make(map[eth2p0.Slot]chan struct{})
	resp.mutable.blockRoot = make(map[eth2p0.Slot]eth2p0.Root)
	resp.mutable.blockRootOK = make(map[eth2p0.Slot]chan struct{})

	return resp
}

// SyncCommMember is a stateful structure providing sync committee message and contribution APIs.
type SyncCommMember struct {
	// Immutable state
	eth2Cl   eth2wrap.Client
	epoch    eth2p0.Epoch
	pubkeys  []eth2p0.BLSPubKey
	signFunc SignFunc

	// Mutable state
	mutable struct {
		sync.Mutex

		vals         eth2wrap.ActiveValidators      // Current set of active validators
		duties       syncDuties                     // Sync committee duties
		selections   map[eth2p0.Slot]syncSelections // Sync committee selections per slot
		selectionsOK map[eth2p0.Slot]chan struct{}
		blockRoot    map[eth2p0.Slot]eth2p0.Root // Beacon block root per slot
		blockRootOK  map[eth2p0.Slot]chan struct{}
	}
	dutiesOK chan struct{}
}

func (s *SyncCommMember) Epoch() eth2p0.Epoch {
	return s.epoch
}

func (s *SyncCommMember) setSelections(slot eth2p0.Slot, selections syncSelections) error {
	s.mutable.Lock()
	defer s.mutable.Unlock()

	s.mutable.selections[slot] = selections

	// Mark selections as done
	ch, ok := s.mutable.selectionsOK[slot]
	if !ok {
		ch = make(chan struct{})
		s.mutable.selectionsOK[slot] = ch
	}

	if isClosed(ch) {
		return errors.New("selections already set")
	}

	close(ch)

	return nil
}

// getSelections returns the sync committee selections for the provided slot.
func (s *SyncCommMember) getSelections(slot eth2p0.Slot) syncSelections {
	s.mutable.Lock()
	defer s.mutable.Unlock()

	return s.mutable.selections[slot]
}

// getSelectionsOK returns a channel for sync committee selections. When this channel is closed, it means that selections are ready for this slot.
func (s *SyncCommMember) getSelectionsOK(slot eth2p0.Slot) chan struct{} {
	s.mutable.Lock()
	defer s.mutable.Unlock()

	ch, ok := s.mutable.selectionsOK[slot]
	if !ok {
		ch = make(chan struct{})
		s.mutable.selectionsOK[slot] = ch
	}

	return ch
}

// setBlockRoot sets block root for the slot.
func (s *SyncCommMember) setBlockRoot(slot eth2p0.Slot, blockRoot eth2p0.Root) error {
	s.mutable.Lock()
	defer s.mutable.Unlock()

	s.mutable.blockRoot[slot] = blockRoot

	// Mark block root assigned for the slot
	ch, ok := s.mutable.blockRootOK[slot]
	if !ok {
		ch = make(chan struct{})
		s.mutable.blockRootOK[slot] = ch
	}

	if isClosed(ch) {
		return errors.New("block root already set")
	}

	close(ch)

	return nil
}

// getBlockRoot returns the beacon block root for the provided slot.
func (s *SyncCommMember) getBlockRoot(slot eth2p0.Slot) eth2p0.Root {
	s.mutable.Lock()
	defer s.mutable.Unlock()

	return s.mutable.blockRoot[slot]
}

// getBlockRootOK returns a channel for beacon block root. When this channel is closed, it means that block root is ready for this slot.
func (s *SyncCommMember) getBlockRootOK(slot eth2p0.Slot) chan struct{} {
	s.mutable.Lock()
	defer s.mutable.Unlock()

	ch, ok := s.mutable.blockRootOK[slot]
	if !ok {
		ch = make(chan struct{})
		s.mutable.blockRootOK[slot] = ch
	}

	return ch
}

func (s *SyncCommMember) setDuties(vals eth2wrap.ActiveValidators, duties syncDuties) error {
	s.mutable.Lock()
	defer s.mutable.Unlock()

	if isClosed(s.dutiesOK) {
		return errors.New("duties already set")
	}

	s.mutable.vals = vals
	s.mutable.duties = duties
	close(s.dutiesOK)

	return nil
}

func (s *SyncCommMember) getDuties() syncDuties {
	s.mutable.Lock()
	defer s.mutable.Unlock()

	return s.mutable.duties
}

func (s *SyncCommMember) getVals() eth2wrap.ActiveValidators {
	s.mutable.Lock()
	defer s.mutable.Unlock()

	return s.mutable.vals
}

// PrepareEpoch stores sync committee duties and submits sync committee subscriptions at the start of an epoch.
func (s *SyncCommMember) PrepareEpoch(ctx context.Context) error {
	vals, err := s.eth2Cl.ActiveValidators(ctx)
	if err != nil {
		return err
	}

	duties, err := prepareSyncCommDuties(ctx, s.eth2Cl, vals, s.epoch)
	if err != nil {
		return err
	}

	if err := s.setDuties(vals, duties); err != nil {
		return err
	}

	err = subscribeSyncCommSubnets(ctx, s.eth2Cl, s.epoch, duties)
	if err != nil {
		return err
	}

	return nil
}

// PrepareSlot prepares selection proofs at the start of a slot.
func (s *SyncCommMember) PrepareSlot(ctx context.Context, slot eth2p0.Slot) error {
	wait(ctx, s.dutiesOK)

	selections, err := prepareSyncSelections(ctx, s.eth2Cl, s.signFunc, s.getDuties(), slot)
	if err != nil {
		return err
	}

	return s.setSelections(slot, selections)
}

// Message submits sync committee messages at 1/3rd into the slot. It also sets the beacon block root for the slot.
func (s *SyncCommMember) Message(ctx context.Context, slot eth2p0.Slot) error {
	wait(ctx, s.dutiesOK)

	duties := s.getDuties()
	if len(duties) == 0 {
		return s.setBlockRoot(slot, eth2p0.Root{})
	}

	opts := &eth2api.BeaconBlockRootOpts{Block: "head"}

	eth2Resp, err := s.eth2Cl.BeaconBlockRoot(ctx, opts)
	if err != nil {
		return err
	}

	blockRoot := eth2Resp.Data

	err = submitSyncMessages(ctx, s.eth2Cl, slot, *blockRoot, s.signFunc, duties)
	if err != nil {
		return err
	}

	return s.setBlockRoot(slot, *blockRoot)
}

// Aggregate submits SignedContributionAndProof at 2/3rd into the slot. It does sync committee aggregations.
// It blocks until sync committee selections are ready for this slot.
func (s *SyncCommMember) Aggregate(ctx context.Context, slot eth2p0.Slot) (bool, error) {
	wait(ctx, s.dutiesOK, s.getSelectionsOK(slot), s.getBlockRootOK(slot))

	return aggContributions(ctx, s.eth2Cl, s.signFunc, slot, s.getVals(), s.getSelections(slot), s.getBlockRoot(slot))
}

// prepareSyncCommDuties returns sync committee duties for the epoch.
func prepareSyncCommDuties(ctx context.Context, eth2Cl eth2wrap.Client, vals eth2wrap.ActiveValidators, epoch eth2p0.Epoch) (syncDuties, error) {
	if len(vals) == 0 {
		return nil, nil
	}

	opts := &eth2api.SyncCommitteeDutiesOpts{
		Epoch:   epoch,
		Indices: vals.Indices(),
	}

	eth2Resp, err := eth2Cl.SyncCommitteeDuties(ctx, opts)
	if err != nil {
		return nil, err
	}

	return eth2Resp.Data, nil
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
func prepareSyncSelections(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc,
	duties syncDuties, slot eth2p0.Slot,
) (syncSelections, error) {
	if len(duties) == 0 {
		return nil, nil
	}

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
	eth2Resp, err := eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
	if err != nil {
		return nil, err
	}

	spec := eth2Resp.Data

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
		subcommIdx := uint64(idx) / (commSize / subnetCount)
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
func aggContributions(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc, slot eth2p0.Slot,
	vals eth2wrap.ActiveValidators, selections syncSelections, blockRoot eth2p0.Root,
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
		opts := &eth2api.SyncCommitteeContributionOpts{
			Slot:              selection.Slot,
			SubcommitteeIndex: uint64(selection.SubcommitteeIndex),
			BeaconBlockRoot:   blockRoot,
		}

		eth2Resp, err := eth2Cl.SyncCommitteeContribution(ctx, opts)
		if err != nil {
			return false, err
		}

		contrib := eth2Resp.Data

		vIdx := selection.ValidatorIndex
		contribAndProof := &altair.ContributionAndProof{
			AggregatorIndex: vIdx,
			Contribution:    contrib,
			SelectionProof:  selection.SelectionProof,
		}

		pubkey, ok := vals[vIdx]
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

		sig, err := signFunc(pubkey, sigData[:])
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

// isClosed returns true if the channel is closed.
func isClosed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
