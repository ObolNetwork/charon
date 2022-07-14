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

package tracker

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

// component refers to a core workflow component.
type component int

// Core components arranged in the order data flows through them.
const (
	scheduler component = iota
	fetcher
	consensus
	validatorAPI
	parSigEx
	parSigDB
	sigAgg
)

func (c component) string() string {
	return map[component]string{
		scheduler:    "scheduler",
		fetcher:      "fetcher",
		consensus:    "consensus",
		validatorAPI: "validatorAPI",
		parSigEx:     "parSigEx",
		parSigDB:     "parSigDB",
		sigAgg:       "sigAgg",
	}[c]
}

// event represents an event emitted by a core workflow component.
type event struct {
	duty      core.Duty
	component component
	pubkey    core.PubKey
}

// Tracker represents the component that listens to events from core workflow components.
// It identifies where a duty gets stuck in the course of its execution.
type Tracker struct {
	mu    sync.Mutex
	input chan int64

	// events stores all the events in a particular slot.
	events       map[int64][]event
	deadlineFunc func(core.Duty) time.Time
	quit         chan struct{}

	testChan chan event
	isTest   bool
}

// NewForT returns a new Tracker for use in tests.
func NewForT(deadlineFunc func(core.Duty) time.Time, chanLen int) *Tracker {
	t := NewTracker(deadlineFunc)
	t.isTest = true
	t.testChan = make(chan event, chanLen)

	return t
}

// NewTracker returns a new Tracker.
func NewTracker(deadlineFunc func(core.Duty) time.Time) *Tracker {
	t := &Tracker{
		// Using a buffered channel
		input:        make(chan int64, 10),
		events:       make(map[int64][]event),
		quit:         make(chan struct{}),
		deadlineFunc: deadlineFunc,
	}

	return t
}

// Run blocks and registers events from each component in tracker's input channel.
func (t *Tracker) Run(ctx context.Context) error {
	var (
		currSlot     int64
		slotDeadline <-chan time.Time
	)

	defer close(t.quit)

	for {
		select {
		case <-ctx.Done(): // should only one way to quit
			return ctx.Err()
		case <-t.quit: //
			return nil
		case s := <-t.input: // use deadliner
			if currSlot == 0 || s < currSlot {
				log.Debug(ctx, "Going to an earlier slot", z.I64("slot", currSlot))
				// First event or earlier event.
				currSlot = s
				slotDeadline = time.After(time.Until(t.deadlineFunc(core.Duty{Slot: s})))
			}
			// add data here
		case <-slotDeadline:
			// Case 1: isReadyToAnalyze == true when deadline for slot has exceeded
			// Explanation: if deadline exceeds for slot, we assume no component sends any event for the slot. So, we can
			// consider the slot to be final and ready to be analyzed. In this case we can use canStoreEvent function before
			// storing the event in each component method.

			// Case 2: isReadyToAnalyze == (currSlot - slotToBeAnalyzed) > 10
			// Explanation: We give sufficient time for events to accumulate for the given slot. If there are events
			// after the 10 slots, they would not be considered for analysis and will be silently dropped.
			t.analyzeSlot(ctx, currSlot)
			t.trimToSlot(currSlot)
			currSlot++
			slotDeadline = time.After(time.Until(t.deadlineFunc(core.Duty{Slot: currSlot})))
		}
	}
}

// Stop stops the tracker process.
func (t *Tracker) Stop() {
	close(t.quit)
}

// canStoreEvent returns true if the event can be stored in the events map.
func (t *Tracker) canStoreEvent(duty core.Duty) bool {
	// Logic as per Case 1
	return time.Now().Before(t.deadlineFunc(duty))
}

// storeEvent stores the event as value with the duty as the key.
func (t *Tracker) storeEvent(e event) {
	t.events[e.duty.Slot] = append(t.events[e.duty.Slot], e)
}

// analyzeSlot analyzes the events in a given slot after the slot's deadline is exceeded.
func (t *Tracker) analyzeSlot(ctx context.Context, slot int64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Deadline crossed for this slot.
	log.Debug(ctx, "Slot deadline exceeded", z.I64("slot", slot))

	events := t.events[slot]

	// Sort in reverse order (see order above).
	sort.Slice(events, func(i, j int) bool {
		return events[i].component > events[j].component
	})

	// Case of failed duties
	if events[0].component != sigAgg {
		// duty failed in the next component.
		failedComponent := (events[0].component + 1).string()
		log.Error(ctx, "Duty stuck", errors.New("duty stuck", z.Str("component", failedComponent)))

		return
	}
	// TODO(dhruv): Case of cluster participation (duty success)
}

// trimToSlot trims the events for a given slot.
func (t *Tracker) trimToSlot(slot int64) {
	delete(t.events, slot)
}

// SchedulerEvent inputs event from core.Scheduler component.
func (t *Tracker) SchedulerEvent(ctx context.Context, duty core.Duty, defSet core.DutyDefinitionSet) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for pubkey := range defSet {
		t.storeEvent(event{
			duty:      duty,
			component: scheduler,
			pubkey:    pubkey,
		})
	}

	// select {
	// case <-t.quit:
	// 	case t.input <- duty.Slot:
	// }
	//

	log.Debug(ctx, "Sent events to tracker", z.Str("component", scheduler.string()))

	return nil
}

// FetcherEvent inputs event from core.Fetcher component.
func (t *Tracker) FetcherEvent(ctx context.Context, duty core.Duty, data core.UnsignedDataSet) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for pubkey := range data {
		t.storeEvent(event{
			duty:      duty,
			component: fetcher,
			pubkey:    pubkey,
		})
	}

	t.input <- duty.Slot

	log.Debug(ctx, "Sent events to tracker", z.Str("component", fetcher.string()))

	return nil
}

// ConsensusEvent inputs event from core.Consensus component.
func (t *Tracker) ConsensusEvent(ctx context.Context, duty core.Duty, data core.UnsignedDataSet) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for pubkey := range data {
		t.storeEvent(event{
			duty:      duty,
			component: consensus,
			pubkey:    pubkey,
		})
	}

	t.input <- duty.Slot

	log.Debug(ctx, "Sent events to tracker", z.Str("component", consensus.string()))

	return nil
}

func (t *Tracker) ValidatorAPIEvent(ctx context.Context, duty core.Duty, pubkey core.PubKey) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.storeEvent(event{
		duty:      duty,
		component: validatorAPI,
		pubkey:    pubkey,
	})

	t.input <- duty.Slot

	log.Debug(ctx, "Sent events to tracker", z.Str("component", validatorAPI.string()))
}

// ParSigExEvent inputs event from core.ParSigEx component.
func (t *Tracker) ParSigExEvent(ctx context.Context, duty core.Duty, data core.ParSignedDataSet) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for pubkey := range data {
		t.storeEvent(event{
			duty:      duty,
			component: parSigEx,
			pubkey:    pubkey,
		})
	}

	t.input <- duty.Slot

	log.Debug(ctx, "Sent events to tracker", z.Str("component", parSigEx.string()))

	return nil
}

// ParSigDBInternalEvent inputs event from core.ParSigDB component for Internal store event.
func (t *Tracker) ParSigDBInternalEvent(ctx context.Context, duty core.Duty, data core.ParSignedDataSet) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for pubkey := range data {
		t.storeEvent(event{
			duty:      duty,
			component: parSigDB,
			pubkey:    pubkey,
		})
	}

	t.input <- duty.Slot

	log.Debug(ctx, "Sent events to tracker", z.Str("component", parSigDB.string()))

	return nil
}

// ParSigDBThresholdEvent inputs event from core.ParSigDB component for threshold event.
func (t *Tracker) ParSigDBThresholdEvent(ctx context.Context, duty core.Duty, pubkey core.PubKey, _ []core.ParSignedData) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.storeEvent(event{
		duty:      duty,
		component: parSigDB,
		pubkey:    pubkey,
	})

	t.input <- duty.Slot

	log.Debug(ctx, "Sent events to tracker", z.Str("component", parSigDB.string()))

	return nil
}

// SigAggEvent inputs event from core.SigAgg component.
func (t *Tracker) SigAggEvent(ctx context.Context, duty core.Duty, pubkey core.PubKey, _ core.SignedData) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.storeEvent(event{
		duty:      duty,
		component: sigAgg,
		pubkey:    pubkey,
	})

	t.input <- duty.Slot

	log.Debug(ctx, "Sent events to tracker", z.Str("component", sigAgg.string()))

	return nil
}
