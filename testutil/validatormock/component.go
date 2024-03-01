// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatormock

import (
	"context"
	"sort"
	"sync"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

const (
	// epochWindow is the window size of the lookahead.
	epochWindow = 2

	// delayStartSlots is the number slots to wait before starting validatormock.
	// This is needed to avoid inconsistencies between peers on startup in simnet tests.
	delayStartSlots = 2
)

// scheduleTuple is a tuple of a duty and the time it should be performed.
type scheduleTuple struct {
	duty      core.Duty
	startTime time.Time
}

func New(ctx context.Context,
	eth2ClProvider func() (eth2wrap.Client, error),
	signFunc SignFunc,
	pubkeys []eth2p0.BLSPubKey,
	genesisTime time.Time,
	slotDuration time.Duration,
	slotsPerEpoch uint64,
	builderAPI bool,
) *Component {
	c := &Component{
		eth2ClProvider: eth2ClProvider,
		signFunc:       signFunc,
		pubkeys:        pubkeys,
		meta: specMeta{
			GenesisTime:   genesisTime,
			SlotDuration:  slotDuration,
			SlotsPerEpoch: slotsPerEpoch,
		},
		builderAPI:       builderAPI,
		attestersBySlot:  make(map[uint64]*SlotAttester),
		syncCommsByEpoch: make(map[uint64]*SyncCommMember),
		scheduled:        make(chan scheduleTuple),
	}

	go c.Run(ctx)

	return c
}

// Component manages stateful duties for specified public keys within a sliding window of slots and epochs.
// It maintains a set of duties to be performed within the sliding window, which has a length equal to epochWindow.
// The sliding window begins from the current epoch and instantiates validator roles (e.g., attester, syncCommMember)
// for each slot within the window upon startup or at the beginning of each epoch.
type Component struct {
	// Immutable state.
	eth2ClProvider func() (eth2wrap.Client, error)
	signFunc       SignFunc
	pubkeys        []eth2p0.BLSPubKey
	meta           specMeta
	scheduled      chan scheduleTuple
	builderAPI     bool

	// Mutable state.
	mu               sync.Mutex
	delaySlots       int
	started          bool                       // Whether SlotTicked has been called.
	attestersBySlot  map[uint64]*SlotAttester   // Slot attesters indexed by slot number.
	syncCommsByEpoch map[uint64]*SyncCommMember // SyncCommMember indexed by epoch number.
}

// dutiesForSlot returns the duties that should be performed in the provided slot and types.
// It is basically a reverse-lookup for duties in other slots that should be scheduled in this slot.
//
// It scans a range of slots in lookAheadEpochs to determine which duties should be performed in
// the provided slot.
func dutiesForSlot(slot metaSlot, types ...core.DutyType) map[scheduleTuple]struct{} {
	resp := make(map[scheduleTuple]struct{})
	for _, dutyType := range types {
		dutyStartFuncs, ok := dutyStartTimeFuncsByDuty[dutyType]
		if !ok {
			// Not offset func for duty
			continue
		}

		for _, checkSlot := range slot.Epoch().SlotsForLookAhead(epochWindow) {
			for _, startTimeFunc := range dutyStartFuncs {
				startTime := startTimeFunc(checkSlot)
				if !slot.InSlot(startTime) {
					// DutyType not scheduled in input slot.
					continue
				}

				resp[scheduleTuple{
					duty: core.Duty{
						Type: dutyType,
						Slot: checkSlot.Slot,
					},
					startTime: startTime,
				}] = struct{}{}
			}
		}
	}

	return resp
}

// Run blocks and runs duties asynchronously as they are scheduled.
// It returns when the context is cancelled.
func (m *Component) Run(ctx context.Context) {
	ctx = log.WithTopic(ctx, "vmock")

	for {
		select {
		case <-ctx.Done():
			return
		case next := <-m.scheduled:
			// Schedule duty async
			go func(scheduled scheduleTuple) {
				select {
				case <-ctx.Done():
					return
				case <-sleepUntil(scheduled.startTime):
					err := m.runDuty(ctx, scheduled.duty)
					if err != nil {
						log.Warn(ctx, "Duty failed", err, z.Any("duty", scheduled.duty))
					}
				}
			}(next)
		}
	}
}

// SlotTicked is called when a slot ticks/starts. This is called by the scheduler component.
// This is only called once per slot.
func (m *Component) SlotTicked(ctx context.Context, slot core.Slot) error {
	// Check if we need to wait for sometime to start scheduling duties.
	if m.delayOnStartup() {
		return nil
	}

	return m.scheduleSlot(ctx, metaSlot{Slot: slot.Slot, meta: m.meta})
}

// delayOnStartup returns true if we need to omit performing duties in the upcoming slot.
func (m *Component) delayOnStartup() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.delaySlots == delayStartSlots {
		return false
	}

	m.delaySlots++

	return true
}

// scheduleSlot is called when the slot ticks and schedules duties for the provided slot.
// It schedules all the duties which are expected to be performed in the provided slot.
// On startup or at the start of epoch it also instantiates the epoch state.
func (m *Component) scheduleSlot(ctx context.Context, slot metaSlot) error {
	isStartup := m.isStartup() // Trigger startup duties on first call to this method

	// Manage epoch state on startup or in the first slot of an epoch.
	if isStartup || slot.FirstInEpoch() {
		err := m.manageEpochState(ctx, slot.Epoch())
		if err != nil {
			return err
		}
	}

	// Get duties to perform this slot
	duties := dutiesForSlot(slot, core.AllDutyTypes()...)

	for _, duty := range orderByTime(duties) {
		select {
		case <-ctx.Done():
			return nil
		case m.scheduled <- duty:
		}
	}

	return nil
}

// manageEpochState sets attesters and sync committee members for all the epochs in epochWindow.
func (m *Component) manageEpochState(ctx context.Context, epoch metaEpoch) error {
	// Delete attesters and sync committee members for all epochs in epochWindow in past including the current epoch.
	e := epoch
	for i := 0; i < epochWindow; i++ {
		// Delete attesters.
		m.deleteAttesters(e)

		// Delete sync committee members.
		m.deleteSyncCommMembers(e)

		e = e.Prev()
	}

	// Start attesters for this up to lookAhead epoch if not present (idempotent).
	for i := 0; i < epochWindow; i++ {
		if err := m.startAttesters(epoch); err != nil {
			return err
		}

		if err := m.startSyncCommMembers(ctx, epoch); err != nil {
			return err
		}

		epoch = epoch.Next()
	}

	return nil
}

// runDuty is called to execute the duty at the appropriate time.
func (m *Component) runDuty(ctx context.Context, duty core.Duty) error {
	eth2Cl, err := m.eth2ClProvider()
	if err != nil {
		return err
	}

	metaSlot := metaSlot{
		Slot: duty.Slot,
		meta: m.meta,
	}

	epoch := metaSlot.Epoch().Epoch

	attester := m.slotAttester(duty.Slot)
	syncComm := m.syncCommMember(epoch)

	eth2Slot := eth2p0.Slot(duty.Slot)

	switch duty.Type {
	case core.DutyPrepareAggregator:
		if attester == nil {
			return errors.New("attester is nil", z.Str("duty", duty.String()))
		}

		if err = attester.Prepare(ctx); err != nil {
			return err
		}
	case core.DutyAttester:
		if attester == nil {
			return errors.New("attester is nil", z.Str("duty", duty.String()))
		}

		if err = attester.Attest(ctx); err != nil {
			return err
		}
	case core.DutyAggregator:
		if attester == nil {
			return errors.New("attester is nil", z.Str("duty", duty.String()))
		}

		if _, err = attester.Aggregate(ctx); err != nil {
			return err
		}
	case core.DutyProposer:
		if m.builderAPI {
			return nil
		}

		if err = ProposeBlock(ctx, eth2Cl, m.signFunc, eth2Slot); err != nil {
			return err
		}
	case core.DutyBuilderProposer:
		if !m.builderAPI {
			return nil
		}

		if err = ProposeBlindedBlock(ctx, eth2Cl, m.signFunc, eth2Slot); err != nil {
			return err
		}
	case core.DutyUniversalProposer:
		if err = ProposeUniversalBlock(ctx, eth2Cl, m.signFunc, eth2Slot); err != nil {
			return err
		}
	case core.DutyBuilderRegistration:
		if !m.builderAPI {
			return nil
		}

		regs, err := RegistrationsFromProposerConfig(ctx, eth2Cl)
		if err != nil {
			return err
		}

		for pubshare, reg := range regs {
			err = Register(ctx, eth2Cl, m.signFunc, reg, pubshare)
			if err != nil {
				return err
			}
		}
	case core.DutyPrepareSyncContribution:
		if syncComm == nil {
			return errors.New("syncomm is nil", z.Str("duty", duty.String()))
		}

		if err = syncComm.PrepareSlot(ctx, eth2Slot); err != nil { // Rename to sync.Comm.SelectSyncContribution
			return err
		}
	case core.DutySyncMessage:
		if syncComm == nil {
			return errors.New("syncomm is nil", z.Str("duty", duty.String()))
		}

		if err = syncComm.Message(ctx, eth2Slot); err != nil { // Rename to sync.Comm.SyncMessage
			return err
		}
	case core.DutySyncContribution:
		if syncComm == nil {
			return errors.New("syncomm is nil", z.Str("duty", duty.String()))
		}

		if _, err = syncComm.Aggregate(ctx, eth2Slot); err != nil { // Rename to sync.Comm.AggregateSyncContribution
			return err
		}
	default:
		return errors.New("unexpected duty", z.Str("duty", duty.String()))
	}

	return nil
}

// startAttesters instantiate and sets new attesters for the given epoch.
func (m *Component) startAttesters(epoch metaEpoch) error {
	for _, slot := range epoch.Slots() {
		eth2Cl, err := m.eth2ClProvider()
		if err != nil {
			return err
		}

		attester := NewSlotAttester(eth2Cl, eth2p0.Slot(slot.Slot), m.signFunc, m.pubkeys)
		m.setAttester(attester)
	}

	return nil
}

// startSyncCommMembers instantiate and sets new sync committee members for the given epoch.
func (m *Component) startSyncCommMembers(ctx context.Context, epoch metaEpoch) error {
	eth2Cl, err := m.eth2ClProvider()
	if err != nil {
		return err
	}

	syncCommMem := NewSyncCommMember(eth2Cl, eth2p0.Epoch(epoch.Epoch), m.signFunc, m.pubkeys)
	if err = syncCommMem.PrepareEpoch(ctx); err != nil {
		return err
	}

	m.setSyncCommMember(syncCommMem)

	return nil
}

// deleteAttesters deletes all the attesters in the given epoch.
func (m *Component) deleteAttesters(epoch metaEpoch) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, slot := range epoch.Slots() {
		delete(m.attestersBySlot, slot.Slot)
	}
}

// deleteSyncCommMembers deletes all the sync committee members in the given epoch.
func (m *Component) deleteSyncCommMembers(epoch metaEpoch) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.syncCommsByEpoch, epoch.Epoch)
}

// slotAttester returns attester of the given slot.
func (m *Component) slotAttester(slot uint64) *SlotAttester {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.attestersBySlot[slot] // Make nil values valid noops
}

// syncCommMember returns sync committee member of the given epoch.
func (m *Component) syncCommMember(epoch uint64) *SyncCommMember {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.syncCommsByEpoch[epoch]
}

// isStartup returns true if vmock is just started and sets started field to true.
func (m *Component) isStartup() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	isStartup := !m.started
	m.started = true

	return isStartup
}

// setAttester sets attester with the given slot.
func (m *Component) setAttester(attester *SlotAttester) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.attestersBySlot[uint64(attester.Slot())] = attester
}

// setSyncCommMember sets sync committee member with the given epoch.
func (m *Component) setSyncCommMember(syncCommMem *SyncCommMember) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.syncCommsByEpoch[uint64(syncCommMem.epoch)] = syncCommMem
}

// orderByTime sorts the given set of duties by their start times.
func orderByTime(duties map[scheduleTuple]struct{}) []scheduleTuple {
	var resp []scheduleTuple
	for duty := range duties {
		resp = append(resp, duty)
	}

	sort.Slice(resp, func(i, j int) bool {
		return resp[i].startTime.Before(resp[j].startTime)
	})

	return resp
}

// dutyStartTimeFunc that returns the time at which a duty should be triggered for a given slot.
type dutyStartTimeFunc func(metaSlot) time.Time

// dutyStartTimeFuncsByDuty defines the offsets by duty type.
var dutyStartTimeFuncsByDuty = map[core.DutyType][]dutyStartTimeFunc{
	core.DutyPrepareAggregator:       {startOfPrevEpoch, startOfCurrentEpoch},
	core.DutyAttester:                {fraction(1, 3)}, // 1/3 slot duration
	core.DutyAggregator:              {fraction(2, 3)}, // 2/3 slot duration
	core.DutyProposer:                {slotStartTime},
	core.DutyBuilderProposer:         {slotStartTime},
	core.DutyBuilderRegistration:     {startOfCurrentEpoch},
	core.DutyPrepareSyncContribution: {slotStartTime},
	core.DutySyncMessage:             {fraction(1, 3)},
	core.DutySyncContribution:        {fraction(2, 3)},
}

// startOfPrevEpoch returns the start time of the previous epoch.
func startOfPrevEpoch(slot metaSlot) time.Time {
	return slot.Epoch().Prev().FirstSlot().StartTime()
}

// startOfCurrentEpoch returns the start time of the current epoch.
func startOfCurrentEpoch(slot metaSlot) time.Time {
	return slot.Epoch().FirstSlot().StartTime()
}

// fraction returns a function that calculates slot offset based on the fraction x/y of total slot duration.
func fraction(x, y int64) func(slot metaSlot) time.Time { //nolint:unparam
	return func(slot metaSlot) time.Time {
		offset := slot.Duration() * time.Duration(x) / time.Duration(y)

		return slot.StartTime().Add(offset)
	}
}

// slotStartTime returns the start time of the given slot.
func slotStartTime(slot metaSlot) time.Time {
	return slot.StartTime()
}

// sleepUntil abstracts sleeping until a start time.
var sleepUntil = func(startTime time.Time) <-chan time.Time {
	return time.After(time.Until(startTime))
}
