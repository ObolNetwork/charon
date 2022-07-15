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
	parSigDBInternal
	parSigEx
	parSigDBThreshold
	sigAgg
)

func (c component) string() string {
	return map[component]string{
		scheduler:         "scheduler",
		fetcher:           "fetcher",
		consensus:         "consensus",
		validatorAPI:      "validatorAPI",
		parSigDBInternal:  "parSigDBInternal",
		parSigEx:          "parSigEx",
		parSigDBThreshold: "parSigDBThreshold",
		sigAgg:            "sigAgg",
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
	input chan event

	// events stores all the events in a particular slot.
	events       map[int64][]event
	deadlineFunc func(core.Duty) time.Time
	quit         chan struct{}
}

// NewForT returns a new Tracker for use in tests.
func NewForT(deadlineFunc func(core.Duty) time.Time, chanLen int) *Tracker {
	t := NewTracker(deadlineFunc)
	return t
}

// NewTracker returns a new Tracker.
func NewTracker(deadlineFunc func(core.Duty) time.Time) *Tracker {
	t := &Tracker{
		// Using a buffered channel
		input:        make(chan event),
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
		case <-ctx.Done():
			return ctx.Err()
		case e := <-t.input: // use deadliner
			if currSlot == 0 {
				currSlot = e.duty.Slot
			}
			t.storeEvent(e)
		case <-slotDeadline:
			t.analyzeSlot(ctx, currSlot)
			t.trimToSlot(currSlot)
			currSlot++
			slotDeadline = time.After(time.Until(t.deadlineFunc(core.Duty{Slot: currSlot})))
		}
	}
}

// storeEvent stores the event as value with the duty as the key.
func (t *Tracker) storeEvent(e event) {
	t.events[e.duty.Slot] = append(t.events[e.duty.Slot], e)
}

// analyzeSlot analyzes the events in a given slot after the slot's deadline is exceeded.
func (t *Tracker) analyzeSlot(ctx context.Context, slot int64) {
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
	for pubkey := range defSet {
		select {
		case <-t.quit:
			return nil
		default:
			t.input <- event{
				duty:      duty,
				component: scheduler,
				pubkey:    pubkey,
			}
		}
	}

	log.Debug(ctx, "Sent events to tracker", z.Str("component", scheduler.string()))

	return nil
}

// FetcherEvent inputs event from core.Fetcher component.
func (t *Tracker) FetcherEvent(ctx context.Context, duty core.Duty, data core.UnsignedDataSet) error {
	for pubkey := range data {
		select {
		case <-t.quit:
			return nil
		default:
			t.input <- event{
				duty:      duty,
				component: fetcher,
				pubkey:    pubkey,
			}
		}
	}

	log.Debug(ctx, "Sent events to tracker", z.Str("component", fetcher.string()))

	return nil
}

// ConsensusEvent inputs event from core.Consensus component.
func (t *Tracker) ConsensusEvent(ctx context.Context, duty core.Duty, data core.UnsignedDataSet) error {
	for pubkey := range data {
		select {
		case <-t.quit:
			return nil
		default:
			t.input <- event{
				duty:      duty,
				component: consensus,
				pubkey:    pubkey,
			}
		}
	}

	log.Debug(ctx, "Sent events to tracker", z.Str("component", consensus.string()))

	return nil
}

// ValidatorAPIEvent inputs events from core.ValidatorAPI component.
func (t *Tracker) ValidatorAPIEvent(ctx context.Context, duty core.Duty, data core.ParSignedDataSet) {
	for pubkey := range data {
		select {
		case <-t.quit:
			return
		default:
			t.input <- event{
				duty:      duty,
				component: validatorAPI,
				pubkey:    pubkey,
			}
		}
	}

	log.Debug(ctx, "Sent events to tracker", z.Str("component", validatorAPI.string()))
}

// ParSigExEvent inputs event from core.ParSigEx component.
func (t *Tracker) ParSigExEvent(ctx context.Context, duty core.Duty, data core.ParSignedDataSet) error {
	for pubkey := range data {
		select {
		case <-t.quit:
			return nil
		default:
			t.input <- event{
				duty:      duty,
				component: parSigEx,
				pubkey:    pubkey,
			}
		}
	}

	log.Debug(ctx, "Sent events to tracker", z.Str("component", parSigEx.string()))

	return nil
}

// ParSigDBInternalEvent inputs events from core.ParSigDB component for internal store event.
func (t *Tracker) ParSigDBInternalEvent(ctx context.Context, duty core.Duty, data core.ParSignedDataSet) error {
	for pubkey := range data {
		select {
		case <-t.quit:
			return nil
		default:
			t.input <- event{
				duty:      duty,
				component: parSigDBInternal,
				pubkey:    pubkey,
			}
		}
	}

	log.Debug(ctx, "Sent events to tracker", z.Str("component", parSigDBInternal.string()))

	return nil
}

// ParSigDBThresholdEvent inputs event from core.ParSigDB component for threshold event.
func (t *Tracker) ParSigDBThresholdEvent(ctx context.Context, duty core.Duty, pubkey core.PubKey, _ []core.ParSignedData) error {
	select {
	case <-t.quit:
		return nil
	default:
		t.input <- event{
			duty:      duty,
			component: parSigDBThreshold,
			pubkey:    pubkey,
		}
	}

	log.Debug(ctx, "Sent events to tracker", z.Str("component", parSigDBThreshold.string()))

	return nil
}

// SigAggEvent inputs event from core.SigAgg component.
func (t *Tracker) SigAggEvent(ctx context.Context, duty core.Duty, pubkey core.PubKey, _ core.SignedData) error {
	select {
	case <-t.quit:
		return nil
	default:
		t.input <- event{
			duty:      duty,
			component: sigAgg,
			pubkey:    pubkey,
		}
	}

	log.Debug(ctx, "Sent events to tracker", z.Str("component", sigAgg.string()))

	return nil
}
