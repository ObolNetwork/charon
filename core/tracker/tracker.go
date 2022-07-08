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

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

// Component refers to a core workflow component.
type Component int

// Core components arranged in the order data flows through them.
const (
	Scheduler Component = iota
	Fetcher
	Consensus
	DutyDB
	ValidatorAPI
	ParSigDB
	ParSigEx
	SigAgg
	AggSigDB
	Broadcast
)

// event represents an event emitted by a core workflow component.
type event struct {
	duty      core.Duty
	component Component
	pubkey    core.PubKey
}

// Tracker represents the component that listens to events from core workflow components.
// It identifies where a duty gets stuck in the course of its execution.
type Tracker struct {
	input        chan event
	expiredDuty  chan core.Duty
	events       map[core.Duty][]event
	deadlineFunc func(core.Duty) time.Time

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
		events:       make(map[core.Duty][]event),
		deadlineFunc: deadlineFunc,
	}

	return t
}

// Run blocks and registers events from each component in input channel. It also checks for duty deadline every 2s.
// If deadline exceeds for a duty, it instruments the duty and removes it from the events map.
func (t *Tracker) Run(ctx context.Context) error {
	timer := time.NewTicker(1 * time.Second)
	defer timer.Stop()

	for {
		select {
		case e := <-t.input:
			t.events[e.duty] = append(t.events[e.duty], e)
			if t.isTest {
				t.testChan <- e
			}
		case <-timer.C:
			for duty, events := range t.events {
				if time.Now().After(t.deadlineFunc(duty)) {
					// Deadline crossed for this duty.
					log.Info(ctx, "Duty deadline exceeded", z.Any("duty", duty))

					// Order components
					sort.Slice(events, func(i, j int) bool {
						return events[i].component < events[j].component
					})

					if events[len(events)-1].component != Broadcast {
						// core workflow got stuck somewhere
						log.Info(ctx, "Duty stuck", z.Any("component", events[len(events)-1].component))
					}
				}
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// DutyDB, ValidatorAPI, ParSigDB, AggSigDB and Broadcast components don't provide subscriptions.

// AwaitSchedulerEvent inputs event from core.Scheduler component.
func (t *Tracker) AwaitSchedulerEvent(_ context.Context, duty core.Duty, defSet core.DutyDefinitionSet) error {
	for pubkey := range defSet {
		t.input <- event{
			duty:      duty,
			component: Scheduler,
			pubkey:    pubkey,
		}
	}

	return nil
}

// AwaitFetcherEvent inputs event from core.Fetcher component.
func (t *Tracker) AwaitFetcherEvent(_ context.Context, duty core.Duty, data core.UnsignedDataSet) error {
	for pubkey := range data {
		t.input <- event{
			duty:      duty,
			component: Fetcher,
			pubkey:    pubkey,
		}
	}

	return nil
}

// AwaitConsensusEvent inputs event from core.Consensus component.
func (t *Tracker) AwaitConsensusEvent(_ context.Context, duty core.Duty, data core.UnsignedDataSet) error {
	for pubkey := range data {
		t.input <- event{
			duty:      duty,
			component: Consensus,
			pubkey:    pubkey,
		}
	}

	return nil
}

// AwaitParSigExEvent inputs event from core.ParSigEx component.
func (t *Tracker) AwaitParSigExEvent(_ context.Context, duty core.Duty, data core.ParSignedDataSet) error {
	for pubkey := range data {
		t.input <- event{
			duty:      duty,
			component: ParSigEx,
			pubkey:    pubkey,
		}
	}

	return nil
}

// AwaitSigAggEvent inputs event from core.SigAgg component.
func (t *Tracker) AwaitSigAggEvent(_ context.Context, duty core.Duty, pubkey core.PubKey, _ core.SignedData) error {
	t.input <- event{
		duty:      duty,
		component: SigAgg,
		pubkey:    pubkey,
	}

	return nil
}
