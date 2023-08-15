// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatormock

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

const (
	// dutySubscribeSyncContribution is a custom vmock duty not implemented by the charon core workflow.
	dutySubscribeSyncContribution core.DutyType = 101

	// epochWindow is the window size of the dutyWindowManager.
	epochWindow = 2
)

// scheduleTuple is a tuple of a duty and the time it should be performed.
type scheduleTuple struct {
	duty      core.Duty
	startTime time.Time
}

// dutyWindowManager manages stateful duties over a sliding window of slots and epochs.
type dutyWindowManager struct {
	// Immutable state.
	eth2Cl    eth2wrap.Client
	signFunc  SignFunc
	pubkeys   []eth2p0.BLSPubKey
	meta      specMeta
	scheduled chan scheduleTuple

	// Mutable state.
	mu              sync.Mutex
	started         bool                      // Whether SlotTicked has been called.
	attestersBySlot map[int64]*SlotAttester   // Slot attesters indexed by slot number.
	syncCommsBySlot map[int64]*SyncCommMember // SyncCommMember indexed by slot number.
}

// dutiesForSlotAndTypes returns the duties that should be performed in the provided slot and types.
//
// It scans a range of slots in lookAheadEpochs to determine which duties should be performed in
// the provided slot.
func (m *dutyWindowManager) dutiesForSlotAndTypes(slot metaSlot, types ...core.DutyType) map[scheduleTuple]struct{} {
	var resp = make(map[scheduleTuple]struct{})
	for _, dutyType := range types {
		offsetFunc, ok := offsetFuncs[dutyType]
		if !ok {
			// Not offset func for duty
			continue
		}

		for _, checkSlot := range slot.Epoch().SlotsForLookAhead(epochWindow) {
			startTime := offsetFunc(checkSlot)
			if slot.InSlot(startTime) {
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

	return resp
}

// Run blocks and runs duties asynchronously as they are scheduled.
// It returns when the context is cancelled.
func (m *dutyWindowManager) Run(ctx context.Context) {
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
				case <-sleepUntil(next.startTime):
					err := m.runDuty(ctx, next.duty)
					if err != nil {
						log.Warn(ctx, "Duty failed", err, z.Any("duty", next.duty))
					}
				}
			}(next)
		}
	}
}

// SlotTicked is called when a slot ticks/starts. This is called by the scheduler component.
// This is only called once per slot.
func (m *dutyWindowManager) SlotTicked(_ context.Context, slot core.Slot) error {
	m.scheduleSlot(metaSlot{Slot: slot.Slot, meta: m.meta})

	return nil
}

// scheduleSlot is called when the slot ticks and schedules duties for the provided slot.
func (m *dutyWindowManager) scheduleSlot(slot metaSlot) {
	isStartup := m.isStartup() // Trigger startup duties on first call to this method

	// Manage epoch state on startup or in the first slot of an epoch.
	if isStartup || slot.FirstInEpoch() {
		m.manageEpochState(slot.Epoch())
	}

	// Get duties to perform this slot
	duties := m.dutiesForSlotAndTypes(slot, core.AllDutyTypes()...)

	// If startup, add startup duty types for each of their lookback slots.
	if isStartup {
		for _, lookbackSlot := range slot.Epoch().SlotsForLookBack(epochWindow) {
			for duty := range m.dutiesForSlotAndTypes(lookbackSlot, startupLookbackDuties...) {
				duties[duty] = struct{}{}
			}
		}
	}

	for _, duty := range orderByTime(duties) {
		m.scheduled <- duty
	}
}

func (m *dutyWindowManager) manageEpochState(epoch metaEpoch) {

	// Delete attesters for the previous epoch.
	m.deleteAttesters(epoch.Prev())

	// TODO: Also delete syncCommMembers

	// Start attesters for this up to lookAhead epoch if not present (idempotent).
	for i := 0; i < epochWindow; i++ {
		m.startAttesters(epoch)

		// // TODO: Also start syncCommMembers

		epoch = epoch.Next()
	}
}

// runDuty is called to execute the duty at the appropriate time.
func (m *dutyWindowManager) runDuty(ctx context.Context, duty core.Duty) error {
	attester := m.slotAttester(duty.Slot)
	syncComm := m.syncCommMember(duty.Slot)

	eth2Slot := eth2p0.Slot(duty.Slot)

	switch duty.Type {
	case core.DutyPrepareAggregator:
		attester.Prepare(ctx)
	case core.DutyAttester:
		attester.Attest(ctx)
	case core.DutyAggregator:
		attester.Aggregate(ctx)
	case dutySubscribeSyncContribution:
		syncComm.PrepareEpoch(ctx) // Rename to sync.Comm.SubscribeSyncContribution
	case core.DutyPrepareSyncContribution:
		syncComm.PrepareSlot(ctx, eth2Slot) // Rename to sync.Comm.SelectSyncContribution
	case core.DutySyncMessage:
		syncComm.Message(ctx, eth2Slot) // Rename to sync.Comm.SyncMessage
	case core.DutySyncContribution:
		syncComm.Aggregate(ctx, eth2Slot) // Rename to sync.Comm.AggregateSyncContribution
	}

	return nil
}

func (m *dutyWindowManager) startAttesters(epoch metaEpoch) {
	for _, slot := range epoch.Slots() {
		attester := NewSlotAttester(m.eth2Cl, eth2p0.Slot(slot.Slot), m.signFunc, m.pubkeys)
		m.setAttester(attester)
	}
}

func (m *dutyWindowManager) deleteAttesters(epoch metaEpoch) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, slot := range epoch.Slots() {
		delete(m.attestersBySlot, slot.Slot)
	}
}

func (m *dutyWindowManager) slotAttester(slot int64) *SlotAttester {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.attestersBySlot[slot] // Make nil values valid noops
}

func (m *dutyWindowManager) syncCommMember(slot int64) *SyncCommMember {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.syncCommsBySlot[slot]
}

func (m *dutyWindowManager) isStartup() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	isStartup := !m.started
	return isStartup
}

func (m *dutyWindowManager) setAttester(attester *SlotAttester) {
	m.mu.Lock()
	m.mu.Unlock()
	m.attestersBySlot[int64(attester.Slot())] = attester
}

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

// offsetFunc that returns the time at which a duty should be triggered for a given slot.
type offsetFunc func(metaSlot) time.Time

// offsetFuncs defines the offsets by duty type.
var offsetFuncs = map[core.DutyType]offsetFunc{
	core.DutyPrepareAggregator:       startOfPrevEpoch,
	core.DutyAttester:                fraction(1, 3), // 1/3 slot duration
	core.DutyAggregator:              fraction(2, 3), // 2/3 slot duration
	dutySubscribeSyncContribution:    startOfPrevEpoch,
	core.DutyPrepareSyncContribution: startOfPrevEpoch,
	core.DutySyncMessage:             fraction(1, 3),
	core.DutySyncContribution:        fraction(2, 3),
}

var startupLookbackDuties = []core.DutyType{
	core.DutyPrepareAggregator,
	dutySubscribeSyncContribution,
	core.DutyPrepareSyncContribution,
}

// startOfPrevEpoch returns the start time of the previous epoch.
func startOfPrevEpoch(slot metaSlot) time.Time {
	return slot.Epoch().Prev().FirstSlot().StartTime()
}

// fraction returns a function that calculates slot offset based on the fraction x/y of total slot duration.
func fraction(x, y int64) func(slot metaSlot) time.Time {
	return func(slot metaSlot) time.Time {
		offset := slot.Duration() * time.Duration(x) / time.Duration(y)

		return slot.StartTime().Add(offset)
	}
}

// sleepUntil abstracts sleeping until a start time
var sleepUntil = func(startTime time.Time) <-chan time.Time {
	return time.After(time.Until(startTime))
}

// SetSleepUntilForT sets the sleepUntil function for the duration of the test.
func SetSleepUntilForT(t *testing.T, fn func(startTime time.Time) <-chan time.Time) {
	t.Helper()
	cached := sleepUntil
	sleepUntil = fn

	t.Cleanup(func() {
		sleepUntil = cached
	})
}
