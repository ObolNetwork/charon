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

	"github.com/obolnetwork/charon/app/errors"
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

	// This is an optional field only set by validatorAPI, parSigDBInternal and parSigEx events.
	// shareidx is 1-indexed so 0 indicates unset.
	shareIdx int
}

// Tracker represents the component that listens to events from core workflow components.
// It identifies where a duty gets stuck in the course of its execution.
type Tracker struct {
	input chan event

	// events stores all the events corresponding to a particular duty.
	events    map[core.Duty][]event
	deadliner core.Deadliner
	quit      chan struct{}

	// failedDutyReporter instruments duty failures.
	failedDutyReporter func(ctx context.Context, duty core.Duty, failed bool, component component, reason string)

	// participationReporter instruments duty peer participation.
	participationReporter func(ctx context.Context, duty core.Duty, participatedShares map[int]bool)
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
	ctx = log.WithTopic(ctx, "tracker")
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
			ctx := log.WithCtx(ctx, z.Any("duty", duty))

			// Analyse failed duties
			failed, failedComponent, failedMsg := analyseDutyFailed(duty, t.events[duty])
			t.failedDutyReporter(ctx, duty, failed, failedComponent, failedMsg)

			// Analyse peer participation
			participatedShares, err := analyseParticipation(t.events[duty])
			if err != nil {
				log.Error(ctx, "Invalid participated shares", err)
			} else {
				t.participationReporter(ctx, duty, participatedShares)
			}

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

// failedDutyReporter instruments failed duties.
func failedDutyReporter(ctx context.Context, duty core.Duty, failed bool, component component, reason string) {
	if !failed {
		return
	}

	log.Warn(ctx, "Duty failed", nil,
		z.Any("component", component),
		z.Str("reason", reason))

	failedCounter.WithLabelValues(duty.String(), component.String()).Inc()
}

// analyseParticipation returns a set of share indexes of participated peers.
func analyseParticipation(events []event) (map[int]bool, error) {
	// Set of shareIdx of participated peers.
	resp := make(map[int]bool)

	for _, e := range events {
		// If we get a parSigDBInternal event, then the current node participated successfully.
		// If we get a parSigEx event, then the corresponding peer with e.shareIdx participated successfully.
		if e.component == parSigEx || e.component == parSigDBInternal {
			if e.shareIdx == 0 {
				return nil, errors.New("shareIdx empty", z.Any("component", e.component))
			}
			resp[e.shareIdx] = true
		}
	}

	return resp, nil
}

// newParticipationReporter returns a new participation reporter function which logs and instruments peer participation.
func newParticipationReporter(peers []p2p.Peer) func(context.Context, core.Duty, map[int]bool) {
	// prevAbsent is the set of peers who didn't participated in the last duty.
	var prevAbsent []string

	return func(ctx context.Context, duty core.Duty, participatedShares map[int]bool) {
		var absentPeers []string
		for _, peer := range peers {
			if participatedShares[peer.ShareIdx()] {
				participationGauge.WithLabelValues(duty.Type.String(), peer.Name).Set(1)
			} else {
				absentPeers = append(absentPeers, peer.Name)
				participationGauge.WithLabelValues(duty.Type.String(), peer.Name).Set(0)
			}
		}

		if fmt.Sprint(prevAbsent) != fmt.Sprint(absentPeers) {
			if len(absentPeers) == 0 {
				log.Info(ctx, "All peers participated in duty")
			} else if len(absentPeers) == len(peers) {
				log.Info(ctx, "No peers participated in duty")
			} else {
				log.Info(ctx, "Not all peers participated in duty", z.Any("absent", absentPeers))
			}
		}

		prevAbsent = absentPeers
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
		case t.input <- event{
			duty:      duty,
			component: scheduler,
			pubkey:    pubkey,
		}:
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
		case t.input <- event{
			duty:      duty,
			component: fetcher,
			pubkey:    pubkey,
		}:
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
		case t.input <- event{
			duty:      duty,
			component: consensus,
			pubkey:    pubkey,
		}:
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
		case t.input <- event{
			duty:      duty,
			component: validatorAPI,
			pubkey:    pubkey,
		}:
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
		case t.input <- event{
			duty:      duty,
			component: parSigEx,
			pubkey:    pubkey,
			shareIdx:  pSig.ShareIdx,
		}:
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
		case t.input <- event{
			duty:      duty,
			component: parSigDBInternal,
			pubkey:    pubkey,
			shareIdx:  pSig.ShareIdx,
		}:
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
	case t.input <- event{
		duty:      duty,
		component: parSigDBThreshold,
		pubkey:    pubkey,
	}:
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
	case t.input <- event{
		duty:      duty,
		component: sigAgg,
		pubkey:    pubkey,
	}:
	}

	return nil
}
