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

	sentinel
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

	// events stores all the events corresponding to a particular duty.
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
// It also analyses and reports the duties whose deadline gets crossed.
func (t *Tracker) Run(ctx context.Context) error {
	defer close(t.quit)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-t.input:
			// TODO(dhruv): Do not store events for expired duties.
			t.events[e.duty] = append(t.events[e.duty], e)
			t.deadliner.Add(e.duty)
		case duty := <-t.deadliner.C():
			failed, failedComponent, failedMsg := analyseFailedDuty(duty, t.events[duty])

			t.reportFailedDuty(duty, failed, failedComponent, failedMsg)

			// TODO(dhruv): Case of cluster participation (duty success)
			// t.analyseClusterParticipation()
			delete(t.events, duty)
		}
	}
}

// analyseFailedDuty analyzes the events for a deadlined duty. It returns true if the duty didn't complete the sigagg component.
// If it failed, it also returns the component it failed at and a human friendly error message.
func analyseFailedDuty(duty core.Duty, es []event) (bool, component, string) {
	events := make([]event, len(es))
	copy(events, es)

	// Sort in reverse order (see order above).
	sort.Slice(events, func(i, j int) bool {
		return events[i].component > events[j].component
	})

	if len(events) == 0 {
		return false, sentinel, "No events to analyse"
	}

	if events[0].component == sigAgg {
		// Duty completed successfully
		return false, sigAgg, ""
	}

	return true, events[0].component + 1, fmt.Sprintf("%s failed in %s component", duty.String(), (events[0].component + 1).String())
}

// reportFailedDuty logs and instruments the duty. It ignores non-failed duties.
func (*Tracker) reportFailedDuty(core.Duty, bool, component, string) {
	// TODO(dhruv): instrument failed duty
}

// SchedulerEvent inputs event from core.Scheduler component.
func (t *Tracker) SchedulerEvent(ctx context.Context, duty core.Duty, defSet core.DutyDefinitionSet) error {
	for pubkey := range defSet {
		select {
		case <-ctx.Done():
			return ctx.Err()
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
func (t *Tracker) FetcherEvent(ctx context.Context, duty core.Duty, data core.UnsignedDataSet) error {
	for pubkey := range data {
		select {
		case <-ctx.Done():
			return ctx.Err()
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
func (t *Tracker) ConsensusEvent(ctx context.Context, duty core.Duty, data core.UnsignedDataSet) error {
	for pubkey := range data {
		select {
		case <-ctx.Done():
			return ctx.Err()
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
func (t *Tracker) ValidatorAPIEvent(ctx context.Context, duty core.Duty, data core.ParSignedDataSet) {
	for pubkey := range data {
		select {
		case <-ctx.Done():
			return
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
func (t *Tracker) ParSigExEvent(ctx context.Context, duty core.Duty, data core.ParSignedDataSet) error {
	for pubkey := range data {
		select {
		case <-ctx.Done():
			return ctx.Err()
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
func (t *Tracker) ParSigDBInternalEvent(ctx context.Context, duty core.Duty, data core.ParSignedDataSet) error {
	for pubkey := range data {
		select {
		case <-ctx.Done():
			return ctx.Err()
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
func (t *Tracker) ParSigDBThresholdEvent(ctx context.Context, duty core.Duty, pubkey core.PubKey, _ []core.ParSignedData) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
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
func (t *Tracker) SigAggEvent(ctx context.Context, duty core.Duty, pubkey core.PubKey, _ core.SignedData) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
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
