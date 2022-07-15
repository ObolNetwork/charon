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

	"github.com/obolnetwork/charon/core"
)

//go:generate stringer -type=component

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

	// events stores all the events in a particular duty.
	events    map[core.Duty][]event
	deadliner core.Deadliner
	quit      chan struct{}
}

// NewTracker returns a new Tracker.
func NewTracker(deadliner core.Deadliner) *Tracker {
	t := &Tracker{
		input:     make(chan event),
		events:    make(map[core.Duty][]event),
		quit:      make(chan struct{}),
		deadliner: deadliner,
	}

	return t
}

// Run blocks and registers events from each component in tracker's input channel.
func (t *Tracker) Run(ctx context.Context) error {
	defer close(t.quit)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-t.input:
			// TODO(dhruv): do not store events for expired duties
			t.events[e.duty] = append(t.events[e.duty], e)
			t.deadliner.Add(e.duty)
		case duty := <-t.deadliner.C():
			t.analyseDuty(duty)
			delete(t.events, duty)
		}
	}
}

// analyzeDuty analyzes the events for a given duty after the duty's deadline is exceeded.
func (t *Tracker) analyseDuty(duty core.Duty) {
	events := t.events[duty]

	// Sort in reverse order (see order above).
	sort.Slice(events, func(i, j int) bool {
		return events[i].component > events[j].component
	})

	if events[0].component == sigAgg {
		// Duty completed successfully
		// TODO(dhruv): Case of cluster participation (duty success)
		// t.analyseClusterParticipation()
		return
	}

	// Duty has failed
	t.reportFailedDuties(duty, events[0].component+1)
}

func (*Tracker) reportFailedDuties(core.Duty, component) {
	// TODO(dhruv): instrument failed duty
}

// SchedulerEvent inputs event from core.Scheduler component.
func (t *Tracker) SchedulerEvent(_ context.Context, duty core.Duty, defSet core.DutyDefinitionSet) error {
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

	return nil
}

// FetcherEvent inputs event from core.Fetcher component.
func (t *Tracker) FetcherEvent(_ context.Context, duty core.Duty, data core.UnsignedDataSet) error {
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

	return nil
}

// ConsensusEvent inputs event from core.Consensus component.
func (t *Tracker) ConsensusEvent(_ context.Context, duty core.Duty, data core.UnsignedDataSet) error {
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

	return nil
}

// ValidatorAPIEvent inputs events from core.ValidatorAPI component.
func (t *Tracker) ValidatorAPIEvent(_ context.Context, duty core.Duty, data core.ParSignedDataSet) {
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
}

// ParSigExEvent inputs event from core.ParSigEx component.
func (t *Tracker) ParSigExEvent(_ context.Context, duty core.Duty, data core.ParSignedDataSet) error {
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

	return nil
}

// ParSigDBInternalEvent inputs events from core.ParSigDB component for internal store event.
func (t *Tracker) ParSigDBInternalEvent(_ context.Context, duty core.Duty, data core.ParSignedDataSet) error {
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

	return nil
}

// ParSigDBThresholdEvent inputs event from core.ParSigDB component for threshold event.
func (t *Tracker) ParSigDBThresholdEvent(_ context.Context, duty core.Duty, pubkey core.PubKey, _ []core.ParSignedData) error {
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

	return nil
}

// SigAggEvent inputs event from core.SigAgg component.
func (t *Tracker) SigAggEvent(_ context.Context, duty core.Duty, pubkey core.PubKey, _ core.SignedData) error {
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

	return nil
}
