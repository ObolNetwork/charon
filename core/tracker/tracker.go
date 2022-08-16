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
	participationReporter func(ctx context.Context, duty core.Duty, participatedShares map[int]bool, unexpectedPeers map[int]bool)
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
			failed, failedComponent, failedMsg := analyseDutyFailed(duty, t.events)
			t.failedDutyReporter(ctx, duty, failed, failedComponent, failedMsg)

			// Analyse peer participation
			participatedShares, unexpectedShares := analyseParticipation(duty, t.events)
			t.participationReporter(ctx, duty, participatedShares, unexpectedShares)

			delete(t.events, duty)
		}
	}
}

// dutyFailedComponent returns true if the duty failed. It also returns the component where the duty got stuck.  If the duty didn't get stuck, it
// returns the sigAgg component. It assumes that all the input events are for a single duty.
func dutyFailedComponent(es []event) (bool, component) {
	events := make([]event, len(es))
	copy(events, es)

	// Sort in reverse order (see order above).
	sort.Slice(events, func(i, j int) bool {
		return events[i].component > events[j].component
	})

	if len(events) == 0 {
		return false, sentinel
	}

	c := events[0].component

	return c != sigAgg, c + 1
}

// analyseDutyFailed detects if the given duty failed. It returns false if the duty didn't fail, i.e., the duty didn't get stuck and completes the sigAgg component.
// It returns true if the duty failed. It also returns the component where the duty got stuck and a human friendly error message explaining why.
func analyseDutyFailed(duty core.Duty, allEvents map[core.Duty][]event) (bool, component, string) {
	var (
		failed bool
		comp   component
		msg    string
	)

	failed, comp = dutyFailedComponent(allEvents[duty])
	if !failed {
		return false, sigAgg, ""
	}

	switch comp {
	case fetcher:
		msg = "couldn't fetch duty data from the beacon node"

		if duty.Type == core.DutyProposer || duty.Type == core.DutyBuilderProposer {
			// Proposer duties may fail if core.DutyRandao fails
			f, c := dutyFailedComponent(allEvents[core.NewRandaoDuty(duty.Slot)])
			if f {
				if c == parSigEx { // DutyRandao failed at parSigEx
					msg = "couldn't propose duty as randao failed to exchange partial signatures"
				} else if c == parSigDBThreshold { // DutyRandao failed at parSigDB
					msg = "couldn't propose duty as randao failed due to insufficient partial signatures"
				}
			}
		}
	case consensus:
		msg = "consensus algorithm didn't complete"
	case validatorAPI:
		msg = "signed duty not submitted by local validator client"

		if duty.Type == core.DutyRandao || duty.Type == core.DutyExit || duty.Type == core.DutyBuilderProposer {
			// These duties start from vapi and may fail even when VC submits signed duty but BN is down
			msg = "signed duty not submitted by local validator client or couldn't fetch duty data from the beacon node"
		}
	case parSigDBInternal:
		msg = "partial signature database didn't trigger partial signature exchange"
	case parSigEx:
		msg = "no partial signature received from peers"
	case parSigDBThreshold:
		msg = "insufficient partial signatures received, minimum required threshold not reached"
	default:
		msg = fmt.Sprintf("%s duty failed at %s", duty.String(), comp.String())
	}

	return true, comp, msg
}

// failedDutyReporter instruments failed duties.
func failedDutyReporter(ctx context.Context, duty core.Duty, failed bool, component component, reason string) {
	if !failed {
		return
	}

	log.Warn(ctx, "Duty failed", nil,
		z.Any("component", component),
		z.Str("reason", reason))

	failedCounter.WithLabelValues(duty.Type.String(), component.String()).Inc()
}

// analyseParticipation returns a set of share indexes of participated peers.
func analyseParticipation(duty core.Duty, allEvents map[core.Duty][]event) (map[int]bool, map[int]bool) {
	// Set of shareIdx of participated peers.
	resp := make(map[int]bool)
	unexpectedShares := make(map[int]bool)

	for _, e := range allEvents[duty] {
		// If we get a parSigDBInternal event, then the current node participated successfully.
		// If we get a parSigEx event, then the corresponding peer with e.shareIdx participated successfully.
		if e.component == parSigEx {
			if !isParSigEventExpected(duty, e.pubkey, allEvents) {
				unexpectedShares[e.shareIdx] = true
				continue
			}

			resp[e.shareIdx] = true
		} else if e.component == parSigDBInternal {
			if !isParSigEventExpected(duty, e.pubkey, allEvents) {
				unexpectedShares[e.shareIdx] = true
				continue
			}

			resp[e.shareIdx] = true
		}
	}

	return resp, unexpectedShares
}

// isParSigEventExpected return true if partially signed data events is expected for the given duty and pubkey.
// Partially signed data events are generated by parsigex and parsigdb.
func isParSigEventExpected(duty core.Duty, pubkey core.PubKey, allEvents map[core.Duty][]event) bool {
	// Cannot validate validatorAPI triggered duties.
	if duty.Type == core.DutyExit || duty.Type == core.DutyBuilderRegistration {
		return true
	}

	if duty.Type == core.DutyRandao {
		// Check that if we got DutyProposer event from scheduler.
		for _, e := range allEvents[core.NewProposerDuty(duty.Slot)] {
			if e.component == scheduler && e.pubkey == pubkey {
				return true
			}
		}

		// Check that if we got DutyBuilderProposer event from scheduler.
		for _, e := range allEvents[core.NewBuilderProposerDuty(duty.Slot)] {
			if e.component == scheduler && e.pubkey == pubkey {
				return true
			}
		}
	}

	// For all other duties check for scheduler event.
	for _, e := range allEvents[duty] {
		if e.component == scheduler && e.pubkey == pubkey {
			return true
		}
	}

	return false
}

// newParticipationReporter returns a new participation reporter function which logs and instruments peer participation
// and unexpectedPeers.
func newParticipationReporter(peers []p2p.Peer) func(context.Context, core.Duty, map[int]bool, map[int]bool) {
	// prevAbsent is the set of peers who didn't participate in the last duty.
	var prevAbsent []string

	return func(ctx context.Context, duty core.Duty, participatedShares map[int]bool, unexpectedShares map[int]bool) {
		var absentPeers []string
		for _, peer := range peers {
			if participatedShares[peer.ShareIdx()] {
				participationGauge.WithLabelValues(duty.Type.String(), peer.Name).Set(1)
			} else if unexpectedShares[peer.ShareIdx()] {
				log.Warn(ctx, "Unexpected event found", nil, z.Str("peer", peer.Name), z.Str("duty", duty.String()))
				unexpectedEventsCounter.WithLabelValues(peer.Name).Inc()
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
