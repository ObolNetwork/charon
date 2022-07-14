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
	mu sync.Mutex

	// input represents the channel where each component pushes it slots.
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
		input:        make(chan int64, 10),
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
		case s := <-t.input:
			if currSlot == 0 || s < currSlot {
				// First event or earlier event.
				currSlot = s
				slotDeadline = time.After(time.Until(t.deadlineFunc(core.Duty{Slot: s})))
			}
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
// T0DO(xenowits): Complete the function below.
func (t *Tracker) analyzeSlot(slot int64) {
	for _, event := range t.events[slot] {
		fmt.Printf("%v\n", event)
	}
}

// trimToSlot trims the events for a given slot.
func (t *Tracker) trimToSlot(slot int64) {
	delete(t.events, slot)
}

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

	t.input <- duty.Slot

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

	t.input <- duty.Slot

	return nil
}

// ConsensusEvent inputs event from core.Consensus component.
func (t *Tracker) ConsensusEvent(_ context.Context, duty core.Duty, data core.UnsignedDataSet) error {
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

	return nil
}

func (t *Tracker) ValidatorAPIEvent(_ context.Context, duty core.Duty, pubkey core.PubKey) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.storeEvent(event{
		duty:      duty,
		component: validatorAPI,
		pubkey:    pubkey,
	})

	t.input <- duty.Slot

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

	t.input <- duty.Slot

	return nil
}

// ParSigDBInternalEvent inputs event from core.ParSigDB component for Internal store event.
func (t *Tracker) ParSigDBInternalEvent(_ context.Context, duty core.Duty, data core.ParSignedDataSet) error {
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

	return nil
}

// ParSigDBThresholdEvent inputs event from core.ParSigDB component for threshold event.
func (t *Tracker) ParSigDBThresholdEvent(_ context.Context, duty core.Duty, pubkey core.PubKey, _ []core.ParSignedData) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.storeEvent(event{
		duty:      duty,
		component: parSigDB,
		pubkey:    pubkey,
	})

	t.input <- duty.Slot

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

	t.input <- duty.Slot

	return nil
}
