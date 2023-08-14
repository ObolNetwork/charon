// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatormock

import (
	"context"
	"sort"
	"sync"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/eth2util/signing"
)

type Epoch struct {
	Epoch     int64
	FirstSlot int64
	LastSlot  int64
	Slots     []int64
	SlotsLen  int64
}

func (e Epoch) Next() Epoch {}
func (e Epoch) Prev() Epoch {}

type AttesterManager struct {
	// Immutable state.
	eth2Cl   eth2wrap.Client
	signFunc SignFunc
	pubkeys  []eth2p0.BLSPubKey

	// Mutable state.
	mu              sync.Mutex
	started         bool
	slots           map[int64]core.Slot       // Slots indexed by slot number.
	epochs          map[int64]Epoch           // Epochs indexed by epoch number.
	attestersBySlot map[int64]*SlotAttester   // Slot attesters indexed by slot number.
	syncCommsBySlot map[int64]*SyncCommMember // SyncCommMember indexed by slot number.
}

const (
	// dutySubscribeSyncContribution is a custom vmock duty not implemented by the charon core workflow.
	dutySubscribeSyncContribution core.DutyType = 101
)

type absDuty struct {
	duty      core.Duty
	startTime time.Time
}

func (m *AttesterManager) dutiesInSlot(currSlot core.Slot, isStartup bool) map[absDuty]struct{} {
	startTime := currSlot.Time                          // Including
	endTime := currSlot.Time.Add(currSlot.SlotDuration) // Excluding
	inCurrSlot := func(t time.Time) bool {
		return t.Compare(startTime) > 0 && t.Compare(endTime) < 1
	}

	// Check if any duty type in a range of "close slots" should be scheduled in this slot
	currEpoch := m.wrapEpoch(currSlot.Epoch())
	const lookAheadEpochs = 2
	firstEpochFirstSlot := currEpoch.FirstSlot
	lastEpochLastSlot := currEpoch.LastSlot + currEpoch.SlotsLen*lookAheadEpochs

	resp := make(map[absDuty]struct{})
	for _, dutyType := range core.AllDutyTypes() {
		for closeSlot := m.wrapSlot(firstEpochFirstSlot); closeSlot.Slot < lastEpochLastSlot; closeSlot.Next() {
			offset, ok := slotOffsets[dutyType](closeSlot, isStartup, m)
			startTime := currSlot.Time.Add(offset)
			if !ok {
				// None of this duty type in this close slot
				continue
			} else if !inCurrSlot(startTime) {
				// Duty not current.
				continue
			}

			resp[absDuty{
				duty: core.Duty{
					Type: dutyType,
					Slot: closeSlot.Slot,
				},
				startTime: startTime,
			}] = struct{}{}
		}
	}

	return resp
}

// SlotTicked is called when a slot ticks/starts. This is called by the scheduler component.
// This is only called once per slot.
func (m *AttesterManager) SlotTicked(ctx context.Context, slot core.Slot) error {
	// Manage epoch state on startup or in the first slot of an epoch.
	isStartup := m.isStartup()
	epoch := m.wrapEpoch(slot.Epoch())
	if isStartup || slot.FirstInEpoch() {
		m.manageEpochState(epoch)
	}

	// Get duties to perform this slot
	duties := m.dutiesInSlot(slot, isStartup)

	// If startup, add duties for the first slot of the epoch
	if isStartup {
		for duty := range m.dutiesInSlot(m.wrapSlot(epoch.FirstSlot), true) {
			duties[duty] = struct{}{}
		}
	}

	for _, duty := range orderByTime(duties) {
		time.Sleep(time.Until(duty.startTime))
		m.runDuty(ctx, duty.duty.Type, m.wrapSlot(duty.duty.Slot))
	}

	return nil
}

func (m *AttesterManager) manageEpochState(epoch Epoch) error {
	// Start attesters for this epoch if not present (idempotent).
	if err := m.startAttesters(epoch); err != nil {
		return err
	}

	// Start attesters for the next epoch as well (idempotent).
	if err := m.startAttesters(epoch.Next()); err != nil {
		return err
	}

	// Delete attesters for the previous epoch.
	if err := m.deleteAttesters(epoch.Prev()); err != nil {
		return err
	}

	return nil
}

func orderByTime(duties map[absDuty]struct{}) []absDuty {
	var resp []absDuty
	for duty := range duties {
		resp = append(resp, duty)
	}
	sort.Slice(resp, func(i, j int) bool {
		return resp[i].startTime.Before(resp[j].startTime)
	})

	return resp
}

// runDuty is called to execute the duty type at the appropriate time.
func (m *AttesterManager) runDuty(ctx context.Context, typ core.DutyType, slot core.Slot) error {
	attester := m.slotAttester(slot)
	syncComm := m.syncCommMember(slot)

	switch typ {
	case core.DutyPrepareAggregator:
		attester.Prepare(ctx)
	case core.DutyAttester:
		attester.Attest(ctx)
	case core.DutyAggregator:
		attester.Aggregate(ctx)
	case dutySubscribeSyncContribution:
		syncComm.PrepareEpoch(ctx) // Rename to sync.Comm.SubscribeSyncContribution
	case core.DutyPrepareSyncContribution:
		syncComm.PrepareSlot(ctx, slot) // Rename to sync.Comm.SelectSyncContribution
	case core.DutySyncMessage:
		syncComm.Message(ctx, slot) // Rename to sync.Comm.SyncMessage
	case core.DutySyncContribution:
		syncComm.Aggregate(ctx, slot) // Rename to sync.Comm.AggregateSyncContribution
	case core.DutyProposer:
		m.proposeBlock(ctx, slot)
	case core.DutyBuilderProposer:
		m.proposeBlindedBlock(ctx, slot)
	}

	return nil
}

func (m *AttesterManager) wrapSlot(slot int64) core.Slot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.slots[slot]
}

func (m *AttesterManager) wrapEpoch(epoch int64) Epoch {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.epochs[epoch]
}

func (m *AttesterManager) startAttesters(epoch Epoch) error {
	// Start slot attesters for the provided epoch. Call Prepare method on each async.
	for slot := epoch.FirstSlot; slot <= epoch.LastSlot; slot++ {
		attester := NewSlotAttester(m.eth2Cl, slot, m.signFunc, m.pubkeys)
		m.setAttester(attester)
	}
}

func (m *AttesterManager) deleteAttesters(epoch Epoch) error {
	// Delete slot attesters for the provided epoch.
	// Note must be called once for each epoch started above.
}

func (m *AttesterManager) slotAttester(slot core.Slot) *SlotAttester {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.attestersBySlot[slot.Slot] // Make nil values valid noops
}

func (m *AttesterManager) syncCommMember(slot core.Slot) *SyncCommMember {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.syncCommsBySlot[slot.Slot]
}

func (m *AttesterManager) isStartup() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	isStartup := !m.started
	return isStartup
}

func (m *AttesterManager) proposeBlock(ctx context.Context, slot core.Slot) error {
	return ProposeBlock(ctx, m.eth2Cl, m.signFunc, slot)
}

func (m *AttesterManager) proposeBlindedBlock(ctx context.Context, slot core.Slot) error {
	return ProposeBlindedBlock(ctx, m.eth2Cl, m.signFunc, slot)
}

func (m *AttesterManager) setAttester(attester *SlotAttester) {
	m.mu.Lock()
	m.mu.Unlock()
	m.attestersBySlot[attester.Slot()] = attester
}

type wrapper interface {
	wrapSlot(slot int64) core.Slot
	wrapEpoch(epoch int64) Epoch
}

type offsetFunc func(core.Slot, bool, wrapper) (time.Duration, bool)

// slotOffsets defines the offsets at which the duties should be triggered.
var slotOffsets = map[core.DutyType]offsetFunc{
	core.DutyPrepareAggregator:       startOfPrevEpochOrStartup,
	core.DutyAttester:                fraction(1, 3), // 1/3 slot duration
	core.DutyAggregator:              fraction(2, 3), // 2/3 slot duration
	dutySubscribeSyncContribution:    startOfPrevEpochOrStartup,
	core.DutyPrepareSyncContribution: startOfPrevEpochOrStartup,
	core.DutySyncMessage:             fraction(1, 3),
	core.DutySyncContribution:        fraction(2, 3),
	core.DutyProposer:                startOfSlot,
	core.DutyBuilderProposer:         startOfSlot,
}

func startOfSlot(_ core.Slot, startup bool, _ wrapper) (time.Duration, bool) {
	if startup {
		return 0, false
	}

	return 0, true
}

func startOfPrevEpochOrStartup(slot core.Slot, startup bool, wrapper wrapper) (time.Duration, bool) {
	if startup {
		return 0, true
	}

	return startOfPrevEpoch(slot, wrapper)
}

func startOfPrevEpoch(slot core.Slot, wrapper wrapper) (time.Duration, bool) {
	epoch := wrapper.wrapEpoch(slot.Epoch())
	firstSlot := wrapper.wrapSlot(epoch.FirstSlot)
	return slot.Time.Sub(firstSlot.Time), true
}

// fraction returns a function that calculates slot offset based on the fraction x/y of total slot duration.
func fraction(x, y int64) func(core.Slot, bool, wrapper) (time.Duration, bool) {
	return func(slot core.Slot, isStartup bool, _ wrapper) (time.Duration, bool) {
		if isStartup {
			return 0, false
		}
		return (slot.SlotDuration * time.Duration(x)) / time.Duration(y), true
	}
}

// Type aliases for concise function signatures.
type (
	attDuties     []*eth2v1.AttesterDuty
	attSelections []*eth2exp.BeaconCommitteeSelection
	attDatas      []*eth2p0.AttestationData
)

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
// - Filters active validators for the slot (this could be cached at start of epoch)
// - Fetches attester attDuties for the slot (this could be cached at start of epoch).
// - Prepares aggregation attDuties for slot attesters.
// It panics if called more than once.
// TODO(xenowits): Figure out why is this called twice sometimes (https://github.com/ObolNetwork/charon/issues/1389)).
func (a *SlotAttester) Prepare(ctx context.Context) error {
	vals, err := a.eth2Cl.ActiveValidators(ctx)
	if err != nil {
		return err
	}

	duties, err := prepareAttesters(ctx, a.eth2Cl, vals, a.slot)
	if err != nil {
		return err
	}
	a.setPrepareDuties(vals, duties)

	selections, err := prepareAggregators(ctx, a.eth2Cl, a.signFunc, vals, duties, a.slot)
	if err != nil {
		return err
	}
	a.setPrepareSelections(selections)

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
