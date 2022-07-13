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
	"fmt"
	"sync"
	"time"

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

// event represents an event emitted by a core workflow component.
type event struct {
	duty      core.Duty
	component component
	pubkey    core.PubKey
}

// Tracker represents the component that listens to events from core workflow components.
// It identifies where a duty gets stuck in the course of its execution.
type Tracker struct {
	mu           sync.Mutex
	input        chan event
	expiredDuty  chan core.Duty
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
		input:        make(chan event),
		expiredDuty:  make(chan core.Duty),
		events:       make(map[int64][]event),
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

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.quit:
			return nil
		case e := <-t.input:
			if e.duty.Slot == 0 || e.duty.Slot < currSlot {
				// First event or earlier event.
				currSlot = e.duty.Slot
				slotDeadline = time.After(time.Until(t.deadlineFunc(e.duty)))
			}
			t.storeEvent(e)
		case <-slotDeadline:
			t.analyzeSlot(currSlot)
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

// storeEvent stores the event as value with the duty as the key.
func (t *Tracker) storeEvent(e event) {
	t.events[e.duty.Slot] = append(t.events[e.duty.Slot], e)
}

// analyzeSlot analyzes the events in a given slot after the slot's deadline is exceeded.
func (t *Tracker) analyzeSlot(slot int64) {
	for _, event := range t.events[slot] {
		fmt.Printf("%v\n", event)
	}
}

// trimToSlot trims the events for a given slot.
func (t *Tracker) trimToSlot(slot int64) {
	delete(t.events, slot)
}

// validatorAPI and parSigDB components don't provide subscriptions.

// SchedulerEvent inputs event from core.Scheduler component.
func (t *Tracker) SchedulerEvent(_ context.Context, duty core.Duty, defSet core.DutyDefinitionSet) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for pubkey := range defSet {
		t.storeEvent(event{
			duty:      duty,
			component: scheduler,
			pubkey:    pubkey,
		})
	}

	return nil
}

// FetcherEvent inputs event from core.Fetcher component.
func (t *Tracker) FetcherEvent(_ context.Context, duty core.Duty, data core.UnsignedDataSet) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for pubkey := range data {
		t.storeEvent(event{
			duty:      duty,
			component: fetcher,
			pubkey:    pubkey,
		})
	}

	return nil
}

// ConsensusEvent inputs event from core.Consensus component.
func (t *Tracker) ConsensusEvent(_ context.Context, duty core.Duty, data core.UnsignedDataSet) error {
	t.mu.Lock()
	t.mu.Unlock()

	for pubkey := range data {
		t.storeEvent(event{
			duty:      duty,
			component: consensus,
			pubkey:    pubkey,
		})
	}

	return nil
}

// ParSigExEvent inputs event from core.ParSigEx component.
func (t *Tracker) ParSigExEvent(_ context.Context, duty core.Duty, data core.ParSignedDataSet) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for pubkey := range data {
		t.storeEvent(event{
			duty:      duty,
			component: parSigEx,
			pubkey:    pubkey,
		})
	}

	return nil
}

// SigAggEvent inputs event from core.SigAgg component.
func (t *Tracker) SigAggEvent(_ context.Context, duty core.Duty, pubkey core.PubKey, _ core.SignedData) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.storeEvent(event{
		duty:      duty,
		component: sigAgg,
		pubkey:    pubkey,
	})

	return nil
}
