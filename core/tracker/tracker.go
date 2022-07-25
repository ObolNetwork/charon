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

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/p2p"
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
	shareIdx  int // This is an optional field only set by parSigEx and parSigDBInternal events.
}

// Tracker represents the component that listens to events from core workflow components.
// It identifies where a duty gets stuck in the course of its execution.
type Tracker struct {
	input chan event

	// events stores all the events corresponding to a particular duty.
	events    map[core.Duty][]event
	deadliner core.Deadliner
	quit      chan struct{}

	// failedDutyReporter instruments the duty. It ignores non-failed duties.
	failedDutyReporter func(core.Duty, bool, string, string)

	// participationReporter logs and instruments the participation.
	participationReporter func(context.Context, core.Duty, map[int]bool)
}

// New returns a new Tracker.
func New(deadliner core.Deadliner, peers []p2p.Peer) *Tracker {
	t := &Tracker{
		input:                 make(chan event),
		events:                make(map[core.Duty][]event),
		quit:                  make(chan struct{}),
		deadliner:             deadliner,
		failedDutyReporter:    failedDutyReporter,
		participationReporter: newParticipationReporter(peers),
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
			if !t.deadliner.Add(e.duty) {
				// Ignore expired duties
				continue
			}

			t.events[e.duty] = append(t.events[e.duty], e)
		case duty := <-t.deadliner.C():
			failed, failedComponent, failedMsg := analyseDutyFailed(duty, t.events[duty])
			t.failedDutyReporter(duty, failed, failedComponent.String(), failedMsg)

			currentParticipation := analyseParticipation(t.events[duty])
			t.participationReporter(ctx, duty, currentParticipation)

			delete(t.events, duty)
		}
	}
}

// analyseDutyFailed detects if a duty failed. It returns true if the duty didn't complete the sigagg component.
// If it failed, it also returns the component where it failed and a human friendly error message explaining why.
func analyseDutyFailed(duty core.Duty, es []event) (bool, component, string) {
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

	// TODO(xenowits): Improve message to have more specific details.
	//  Ex: If the duty got stuck during validatorAPI, we can say "the VC didn't successfully submit a signed duty").
	return true, events[0].component + 1, fmt.Sprintf("%s failed in %s component", duty.String(), (events[0].component + 1).String())
}

// failedDutyReporter instruments the duty. It ignores non-failed duties.
// TODO(xenowits): Implement logic for reporting duties.
func failedDutyReporter(core.Duty, bool, string, string) {}

// analyseParticipation returns a set of share indexes of participated peers.
func analyseParticipation(events []event) map[int]bool {
	// Set of shareIdx of participated peers.
	resp := make(map[int]bool)

	for _, e := range events {
		// If we get a parSigDBInternal event, then the current node participated successfully.
		// If we get a parSigEx event, then the corresponding peer with e.shareIdx participated successfully.
		if e.shareIdx > 0 && (e.component == parSigEx || e.component == parSigDBInternal) {
			resp[e.shareIdx] = true
		}
	}

	return resp
}

// newParticipationReporter returns a new participation reporter function which logs and instruments peer participation.
func newParticipationReporter(peers []p2p.Peer) func(context.Context, core.Duty, map[int]bool) {
	// lastParticipation is the set of peers who participated in the last duty.
	lastParticipation := make(map[int]bool)

	return func(ctx context.Context, duty core.Duty, currentParticipation map[int]bool) {
		var absentPeers []string
		for _, peer := range peers {
			if currentParticipation[peer.ShareIdx()] {
				participationGauge.WithLabelValues(duty.String(), peer.Name).Set(1)
			} else {
				absentPeers = append(absentPeers, peer.Name)
				participationGauge.WithLabelValues(duty.String(), peer.Name).Set(0)
			}
		}

		uniqueParticipation := false
		for k, v := range lastParticipation {
			val, ok := currentParticipation[k]
			if !ok || val != v {
				uniqueParticipation = true
				break
			}
		}

		// Avoid identical logs if same set of peers didn't participated.
		if len(absentPeers) > 0 && !uniqueParticipation {
			log.Info(ctx, "Peers didn't participate",
				z.Str("duty", duty.String()),
				z.Any("peers", absentPeers),
			)
		}

		lastParticipation = currentParticipation
	}
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
func (t *Tracker) ValidatorAPIEvent(ctx context.Context, duty core.Duty, data core.ParSignedDataSet) error {
	for pubkey := range data {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.quit:
			return nil
		default:
			t.input <- event{
				duty:      duty,
				component: validatorAPI,
				pubkey:    pubkey,
			}
		}
	}

	return nil
}

// ParSigExEvent inputs event from core.ParSigEx component.
func (t *Tracker) ParSigExEvent(ctx context.Context, duty core.Duty, data core.ParSignedDataSet) error {
	for pubkey, pSig := range data {
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
				shareIdx:  pSig.ShareIdx,
			}
		}
	}

	return nil
}

// ParSigDBInternalEvent inputs events from core.ParSigDB component for internal store event.
func (t *Tracker) ParSigDBInternalEvent(ctx context.Context, duty core.Duty, data core.ParSignedDataSet) error {
	for pubkey, pSig := range data {
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
				shareIdx:  pSig.ShareIdx,
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
