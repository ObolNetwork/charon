// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatormock

import (
	"context"
	"sync"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/eth2util/signing"
)

// Type aliases for concise function signatures.
type (
	attDuties     []*eth2v1.AttesterDuty
	attSelections []*eth2exp.BeaconCommitteeSelection
	attDatas      []*eth2p0.AttestationData
)

// NewAttester creates and returns a new instance of Attester.
func NewAttester(eth2Cl eth2wrap.Client, epoch eth2p0.Epoch, signFunc SignFunc, pubkeys []eth2p0.BLSPubKey) *Attester {
	slotAttesters := make(map[eth2p0.Slot]*SlotAttester)

	return &Attester{
		eth2Cl:        eth2Cl,
		epoch:         epoch,
		pubkeys:       pubkeys,
		signFunc:      signFunc,
		slotAttesters: slotAttesters,
	}
}

// Attester stores SlotAttester instances for current and next epochs.
type Attester struct {
	eth2Cl   eth2wrap.Client
	epoch    eth2p0.Epoch
	pubkeys  []eth2p0.BLSPubKey
	signFunc SignFunc

	mu            sync.Mutex
	slotAttesters map[eth2p0.Slot]*SlotAttester
}

func (a *Attester) SetSlotAttester(slot eth2p0.Slot, attester *SlotAttester) {
	a.mu.Lock()
	a.slotAttesters[slot] = attester
	a.mu.Unlock()
}

func (a *Attester) GetSlotAttester(slot eth2p0.Slot) (*SlotAttester, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	attester, ok := a.slotAttesters[slot]
	if !ok {
		// TODO(xenowits): Should we create a new slot attester for this slot if not found?
		return nil, errors.New("attester for slot not found", z.U64("slot", uint64(slot)))
	}

	return attester, nil
}

// PrepareEpoch prepares attester duties for the current and next epochs and stores the duties in the Attester state.
func (a *Attester) PrepareEpoch(ctx context.Context) error {
	slotsPerEpoch, err := a.eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return err
	}

	// Get list of active validators
	vals, err := a.eth2Cl.ActiveValidators(ctx)
	if err != nil {
		return err
	}

	slotStart, err := a.getCurrentSlot(ctx)
	if err != nil {
		return err
	}
	slotEnd := eth2p0.Slot(uint64(a.epoch+2) * slotsPerEpoch)

	// Prepare attesters for current and next epochs and store them in a map for each slot.
	for slot := slotStart; slot < slotEnd; slot++ {
		s := slot
		go func(slot eth2p0.Slot) {
			attester := NewSlotAttester(a.eth2Cl, slot, a.signFunc, a.pubkeys)
			err := attester.Prepare(ctx, vals)
			if err != nil {
				log.Error(ctx, "Prepare attester", err, z.U64("slot", uint64(slot)))
				return
			}

			a.SetSlotAttester(slot, attester)
		}(s)
	}

	return nil
}

// NewSlotAttester returns a new SlotAttester.
func NewSlotAttester(eth2Cl eth2wrap.Client, slot eth2p0.Slot, signFunc SignFunc, pubkeys []eth2p0.BLSPubKey) *SlotAttester {
	return &SlotAttester{
		eth2Cl:       eth2Cl,
		slot:         slot,
		pubkeys:      pubkeys,
		signFunc:     signFunc,
		dutiesOK:     make(chan struct{}),
		selectionsOK: make(chan struct{}),
		datasOK:      make(chan struct{}),
	}
}

// SlotAttester is a stateful structure providing a slot attestation and aggregation API excluding scheduling.
type SlotAttester struct {
	// Immutable fields
	eth2Cl   eth2wrap.Client
	slot     eth2p0.Slot
	pubkeys  []eth2p0.BLSPubKey
	signFunc SignFunc

	// Mutable fields
	mutable struct {
		sync.Mutex
		vals       eth2wrap.ActiveValidators
		duties     attDuties
		selections attSelections
		datas      attDatas
	}

	dutiesOK     chan struct{}
	selectionsOK chan struct{}
	datasOK      chan struct{}
}

// Slot returns the attester slot.
func (a *SlotAttester) Slot() eth2p0.Slot {
	return a.slot
}

// Prepare should be called at the start of slot, it does the following:
// - Fetches attester duties for the slot.
// - Prepares aggregation duties for slot attesters.
// - Submits beacon committee subscriptions for slot attesters.
// It panics if called more than once.
func (a *SlotAttester) Prepare(ctx context.Context, vals eth2wrap.ActiveValidators) error {
	// Get attester duties
	duties, err := prepareAttesters(ctx, a.eth2Cl, vals, a.slot)
	if err != nil {
		return err
	}
	a.setPrepareDuties(vals, duties)

	// Get attestation aggregators
	selections, err := prepareAggregators(ctx, a.eth2Cl, a.signFunc, vals, duties, a.slot)
	if err != nil {
		return err
	}
	a.setPrepareSelections(selections)

	// Subscribe to beacon committee subnets
	err = subscribeBeaconCommSubnets(ctx, a.eth2Cl, a.slot, duties, selections)
	if err != nil {
		return err
	}

	return nil
}

// Attest should be called at latest 1/3 into the slot, it does slot attestations.
func (a *SlotAttester) Attest(ctx context.Context) error {
	// Wait for Prepare complete
	wait(ctx, a.dutiesOK)

	datas, err := attest(ctx, a.eth2Cl, a.signFunc, a.slot, a.getAttDuties())
	if err != nil {
		return err
	}
	a.setAttestDatas(datas)

	return nil
}

// Aggregate should be called at latest 2/3 into the slot, it does slot attestation aggregations.
func (a *SlotAttester) Aggregate(ctx context.Context) (bool, error) {
	// Wait for Prepare and Attest to complete
	wait(ctx, a.dutiesOK, a.selectionsOK, a.datasOK)

	return aggregate(ctx, a.eth2Cl, a.signFunc, a.slot, a.getVals(),
		a.getAttDuties(), a.getSelections(), a.getDatas())
}

func (a *SlotAttester) setPrepareDuties(vals eth2wrap.ActiveValidators, duties attDuties) {
	a.mutable.Lock()
	defer a.mutable.Unlock()

	a.mutable.vals = vals
	a.mutable.duties = duties
	close(a.dutiesOK)
}

func (a *SlotAttester) setPrepareSelections(selections attSelections) {
	a.mutable.Lock()
	defer a.mutable.Unlock()

	a.mutable.selections = selections
	close(a.selectionsOK)
}

func (a *SlotAttester) setAttestDatas(datas attDatas) {
	a.mutable.Lock()
	defer a.mutable.Unlock()

	a.mutable.datas = datas
	close(a.datasOK)
}

func (a *SlotAttester) getVals() eth2wrap.ActiveValidators {
	a.mutable.Lock()
	defer a.mutable.Unlock()

	return a.mutable.vals
}

func (a *SlotAttester) getAttDuties() attDuties {
	a.mutable.Lock()
	defer a.mutable.Unlock()

	return a.mutable.duties
}

func (a *SlotAttester) getSelections() attSelections {
	a.mutable.Lock()
	defer a.mutable.Unlock()

	return a.mutable.selections
}

func (a *SlotAttester) getDatas() attDatas {
	a.mutable.Lock()
	defer a.mutable.Unlock()

	return a.mutable.datas
}

// wait returns when either all the channels or the context is closed.
func wait(ctx context.Context, chs ...chan struct{}) {
	for _, ch := range chs {
		select {
		case <-ctx.Done():
		case <-ch:
		}
	}
}

// prepareAttesters returns the attesters (including duty and data) for the provided validators and slot.
func prepareAttesters(ctx context.Context, eth2Cl eth2wrap.Client, vals eth2wrap.ActiveValidators,
	slot eth2p0.Slot,
) (attDuties, error) {
	if len(vals) == 0 {
		return nil, nil
	}

	epoch, err := eth2util.EpochFromSlot(ctx, eth2Cl, slot)
	if err != nil {
		return nil, err
	}

	epochDuties, err := eth2Cl.AttesterDuties(ctx, epoch, vals.Indices())
	if err != nil {
		return nil, err
	}

	var duties attDuties
	for _, duty := range epochDuties {
		if duty.Slot != slot {
			continue
		}

		duties = append(duties, duty)
	}

	return duties, nil
}

// prepareAggregators does beacon committee subscription selection for the provided attesters
// and returns the selected aggregators.
func prepareAggregators(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc,
	vals eth2wrap.ActiveValidators, duties attDuties, slot eth2p0.Slot,
) (attSelections, error) {
	if len(duties) == 0 {
		return nil, nil
	}

	epoch, err := eth2util.EpochFromSlot(ctx, eth2Cl, slot)
	if err != nil {
		return nil, err
	}

	slotRoot, err := eth2util.SlotHashRoot(slot)
	if err != nil {
		return nil, err
	}

	sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainSelectionProof, epoch, slotRoot)
	if err != nil {
		return nil, err
	}

	var (
		partials    []*eth2exp.BeaconCommitteeSelection
		commLengths = make(map[eth2p0.ValidatorIndex]uint64)
	)
	for _, duty := range duties {
		pubkey, ok := vals[duty.ValidatorIndex]
		if !ok {
			return nil, errors.New("missing validator index")
		}

		slotSig, err := signFunc(pubkey, sigData[:])
		if err != nil {
			return nil, err
		}

		commLengths[duty.ValidatorIndex] = duty.CommitteeLength

		partials = append(partials, &eth2exp.BeaconCommitteeSelection{
			ValidatorIndex: duty.ValidatorIndex,
			Slot:           duty.Slot,
			SelectionProof: slotSig,
		})
	}

	aggregateSelections, err := eth2Cl.AggregateBeaconCommitteeSelections(ctx, partials)
	if err != nil {
		return nil, err
	}

	var selections attSelections
	for _, selection := range aggregateSelections {
		ok, err := eth2exp.IsAttAggregator(ctx, eth2Cl, commLengths[selection.ValidatorIndex], selection.SelectionProof)
		if err != nil {
			return nil, err
		} else if !ok {
			continue
		}

		selections = append(selections, selection)
	}

	log.Info(ctx, "Mock beacon committee subscription submitted", z.Int("aggregators", len(selections)))

	return selections, nil
}

// attest does attestations for the provided attesters and returns the attestation attDatas.
func attest(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc, slot eth2p0.Slot, duties attDuties,
) (attDatas, error) {
	if len(duties) == 0 {
		return nil, nil
	}

	// Group attDuties by committee.
	dutyByComm := make(map[eth2p0.CommitteeIndex][]*eth2v1.AttesterDuty)
	for _, duty := range duties {
		dutyByComm[duty.CommitteeIndex] = append(dutyByComm[duty.CommitteeIndex], duty)
	}

	var (
		atts  []*eth2p0.Attestation
		datas attDatas
	)
	for commIdx, duties := range dutyByComm {
		data, err := eth2Cl.AttestationData(ctx, slot, commIdx)
		if err != nil {
			return nil, err
		}
		datas = append(datas, data)

		root, err := data.HashTreeRoot()
		if err != nil {
			return nil, errors.Wrap(err, "hash attestation")
		}

		sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainBeaconAttester, data.Target.Epoch, root)
		if err != nil {
			return nil, err
		}

		for _, duty := range duties {
			sig, err := signFunc(duty.PubKey, sigData[:])
			if err != nil {
				return nil, err
			}
			aggBits := bitfield.NewBitlist(duty.CommitteeLength)
			aggBits.SetBitAt(duty.ValidatorCommitteeIndex, true)

			atts = append(atts, &eth2p0.Attestation{
				AggregationBits: aggBits,
				Data:            data,
				Signature:       sig,
			})
		}
	}

	err := eth2Cl.SubmitAttestations(ctx, atts)
	if err != nil {
		return nil, err
	}

	return datas, nil
}

// aggregate does attestation aggregation for the provided validators, attSelections and attestation attDatas and returns true.
// It returns false if aggregation is not required.
func aggregate(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc, slot eth2p0.Slot,
	vals eth2wrap.ActiveValidators, duties attDuties, selections attSelections, datas attDatas,
) (bool, error) {
	if len(selections) == 0 {
		return false, nil
	}

	epoch, err := eth2util.EpochFromSlot(ctx, eth2Cl, slot)
	if err != nil {
		return false, err
	}

	committees := make(map[eth2p0.ValidatorIndex]eth2p0.CommitteeIndex)
	for _, duty := range duties {
		committees[duty.ValidatorIndex] = duty.CommitteeIndex
	}

	var (
		aggs       []*eth2p0.SignedAggregateAndProof
		attsByComm = make(map[eth2p0.CommitteeIndex]*eth2p0.Attestation)
	)
	for _, selection := range selections {
		commIdx, ok := committees[selection.ValidatorIndex]
		if !ok {
			return false, errors.New("missing duty for selection")
		}

		att, ok := attsByComm[commIdx]
		if !ok {
			var err error
			att, err = getAggregateAttestation(ctx, eth2Cl, datas, commIdx)
			if err != nil {
				return false, err
			}
			attsByComm[commIdx] = att
		}

		proof := eth2p0.AggregateAndProof{
			AggregatorIndex: selection.ValidatorIndex,
			Aggregate:       att,
			SelectionProof:  selection.SelectionProof,
		}

		proofRoot, err := proof.HashTreeRoot()
		if err != nil {
			return false, err
		}

		sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainAggregateAndProof, epoch, proofRoot)
		if err != nil {
			return false, err
		}

		pubkey, ok := vals[selection.ValidatorIndex]
		if !ok {
			return false, errors.New("missing validator index", z.U64("vidx", uint64(selection.ValidatorIndex)))
		}

		proofSig, err := signFunc(pubkey, sigData[:])
		if err != nil {
			return false, err
		}

		aggs = append(aggs, &eth2p0.SignedAggregateAndProof{
			Message:   &proof,
			Signature: proofSig,
		})
	}

	if err := eth2Cl.SubmitAggregateAttestations(ctx, aggs); err != nil {
		return false, err
	}

	return true, nil
}

// getAggregateAttestation returns an aggregated attestation for the provided committee.
func getAggregateAttestation(ctx context.Context, eth2Cl eth2wrap.Client, datas attDatas,
	commIdx eth2p0.CommitteeIndex,
) (*eth2p0.Attestation, error) {
	for _, data := range datas {
		if data.Index != commIdx {
			continue
		}

		root, err := data.HashTreeRoot()
		if err != nil {
			return nil, errors.Wrap(err, "hash attestation data")
		}

		return eth2Cl.AggregateAttestation(ctx, data.Slot, root)
	}

	return nil, errors.New("missing attestation data for committee index")
}

// getCurrentSlot returns the current slot.
func (a *Attester) getCurrentSlot(ctx context.Context) (eth2p0.Slot, error) {
	genesisTime, err := a.eth2Cl.GenesisTime(ctx)
	if err != nil {
		return 0, errors.Wrap(err, "get genesis time")
	}

	slotDuration, err := a.eth2Cl.SlotDuration(ctx)
	if err != nil {
		return 0, errors.Wrap(err, "get slot duration")
	}

	currentSlot := int64(time.Since(genesisTime) / slotDuration)

	return eth2p0.Slot(currentSlot), nil
}

// subscribeBeaconCommSubnets submits beacon committee subscriptions at the start of an epoch for the current and next epochs.
func subscribeBeaconCommSubnets(ctx context.Context, eth2Cl eth2wrap.Client, slot eth2p0.Slot, duties attDuties, selections attSelections) error {
	if len(duties) == 0 {
		return nil
	}

	var subs []*eth2v1.BeaconCommitteeSubscription
	for _, duty := range duties {
		// Check if attester is also the aggregator for this slot
		isAggregator := false
		for _, selection := range selections {
			if duty.Slot == selection.Slot && duty.ValidatorIndex == selection.ValidatorIndex {
				isAggregator = true
				break
			}
		}

		subs = append(subs, &eth2v1.BeaconCommitteeSubscription{
			ValidatorIndex:   duty.ValidatorIndex,
			Slot:             duty.Slot,
			CommitteeIndex:   duty.CommitteeIndex,
			CommitteesAtSlot: duty.CommitteesAtSlot,
			IsAggregator:     isAggregator,
		})
	}

	err := eth2Cl.SubmitBeaconCommitteeSubscriptions(ctx, subs)
	if err != nil {
		return err
	}

	log.Info(ctx, "Mock beacon committee subscription submitted", z.Int("slot", int(slot)))

	return nil
}
