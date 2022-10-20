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
	zero component = iota
	scheduler
	fetcher
	consensus
	validatorAPI
	parSigDBInternal
	parSigEx
	parSigDBThreshold
	sigAgg
	sentinel
)

// These constants are used for improving messages for why a duty failed.
const (
	// msgFetcher indicates a duty failed in the fetcher component when it failed
	// to fetch the required data from the beacon node API. This indicates a problem with
	// the upstream beacon node.
	msgFetcher = "couldn't fetch duty data from the beacon node"

	// msgFetcherAggregatorNoAttData indicates an attestation aggregation duty failed in
	// the fetcher component since it couldn't fetch the prerequisite attestation data. This
	// indicates the associated attestation duty failed to obtain a cluster agreed upon value.
	msgFetcherAggregatorNoAttData = "couldn't aggregate attestation due to failed attester duty"

	// msgFetcherAggregatorFewPrepares indicates an attestation aggregation duty failed in
	// the fetcher component since it couldn't fetch the prerequisite aggregated beacon committee selections.
	// This indicates the associated prepare aggregation duty failed due to insufficient partial beacon committee selections
	// submitted by the cluster validator clients.
	msgFetcherAggregatorFewPrepares = "couldn't aggregate attestation due to insufficient partial beacon committee selections"

	// msgFetcherAggregatorZeroPrepares indicates an attestation aggregation duty failed in
	// the fetcher component since it couldn't fetch the prerequisite aggregated beacon committee selections.
	// This indicates the associated prepare aggregation duty failed due to no partial beacon committee selections
	// submitted by the cluster validator clients.
	msgFetcherAggregatorZeroPrepares = "couldn't aggregate attestation due to zero partial beacon committee selections"

	// msgFetcherAggregatorFailedPrepare indicates an attestation aggregation duty failed in
	// the fetcher component since it couldn't fetch the prerequisite aggregated beacon committee selections.
	// This indicates the associated prepare aggregation duty failed.
	msgFetcherAggregatorFailedPrepare = "couldn't aggregate attestation due to failed prepare aggregator duty"

	// msgFetcherProposerFewRandaos indicates a block proposer duty failed in
	// the fetcher component since it couldn't fetch the prerequisite aggregated RANDAO.
	// This indicates the associated randao duty failed due to insufficient partial randao signatures
	// submitted by the cluster validator clients.
	msgFetcherProposerFewRandaos = "couldn't propose block due to insufficient partial randao signatures"

	// msgFetcherProposerZeroRandaos indicates a block proposer duty failed in
	// the fetcher component since it couldn't fetch the prerequisite aggregated RANDAO.
	// This indicates the associated randao duty failed due to no partial randao signatures
	// submitted by the cluster validator clients.
	msgFetcherProposerZeroRandaos = "couldn't propose block due to zero partial randao signatures"

	// msgFetcherProposerZeroRandaos indicates a block proposer duty failed in
	// the fetcher component since it couldn't fetch the prerequisite aggregated RANDAO.
	// This indicates the associated randao duty failed.
	msgFetcherProposerFailedRandao = "couldn't propose block due to failed randao duty"

	// msgFetcherSyncContributionNoSyncMsg indicates a sync contribution duty failed in
	// the fetcher component since it couldn't fetch the prerequisite sync message. This
	// indicates the associated sync message duty failed to obtain a cluster agreed upon value.
	msgFetcherSyncContributionNoSyncMsg = "couldn't fetch sync contribution due to failed sync message duty"

	// msgFetcherSyncContributionFewPrepares indicates a sync contribution duty failed in
	// the fetcher component since it couldn't fetch the prerequisite aggregated sync contribution selections.
	// This indicates the associated prepare sync contribution duty failed due to insufficient partial sync contribution selections
	// submitted by the cluster validator clients.
	msgFetcherSyncContributionFewPrepares = "couldn't fetch sync contribution due to insufficient partial sync contribution selections"

	// msgFetcherSyncContributionZeroPrepares indicates a sync contribution duty failed in
	// the fetcher component since it couldn't fetch the prerequisite aggregated sync contribution selections.
	// This indicates the associated prepare sync contribution duty failed due to no partial sync contribution selections
	// submitted by the cluster validator clients.
	msgFetcherSyncContributionZeroPrepares = "couldn't fetch sync contribution due to zero partial sync contribution selections"

	// msgFetcherSyncContributionFailedPrepare indicates a sync contribution duty failed in
	// the fetcher component since it couldn't fetch the prerequisite aggregated sync contribution selections.
	// This indicates the associated prepare sync contribution duty failed.
	msgFetcherSyncContributionFailedPrepare = "couldn't fetch sync contribution due to failed prepare sync contribution duty"

	// msgConsensus indicates a duty failed in consensus component.
	// This could indicate that insufficient honest peers participated in consensus or p2p network
	// connection problems.
	msgConsensus = "consensus algorithm didn't complete"

	// msgValidatorAPI indicates that partial signature we never submitted by the local
	// validator client. This could indicate that the local validator client is offline,
	// or has connection problems with charon, or has some other problem. See validator client
	// logs for more details.
	msgValidatorAPI = "signed duty not submitted by local validator client"

	// msgParSigDBInternal indicates a bug in the partial signature database as it is unexpected.
	msgParSigDBInternal = "bug: partial signature database didn't trigger partial signature exchange"

	// msgParSigEx indicates that no partial signature for the duty was received from any peer.
	// This indicates all peers are offline or p2p network connection problems.
	msgParSigEx = "no partial signatures received from peers"

	// msgParSigDBThreshold indicates that insufficient partial signatures for the duty was received from peers.
	// This indicates problems with peers or p2p network connection problems.
	msgParSigDBThreshold = "insufficient partial signatures received, minimum required threshold not reached"

	// msgSigAgg indicates that BLS threshold aggregation of sufficient partial signatures failed. This
	// indicates inconsistent signed data. This indicates a bug in charon as it is unexpected.
	msgSigAgg = "bug: threshold aggregation of partial signatures failed due to inconsistent signed data"
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
	events map[core.Duty][]event
	// analyser triggers duty analysis.
	analyser core.Deadliner
	// deleter triggers duty deletion after all associated analysis are done.
	deleter core.Deadliner
	// fromSlot indicates the slot to start tracking events from.
	fromSlot int64
	quit     chan struct{}

	// failedDutyReporter instruments duty failures.
	failedDutyReporter func(ctx context.Context, duty core.Duty, failed bool, component component, reason string)

	// participationReporter instruments duty peer participation.
	participationReporter func(ctx context.Context, duty core.Duty, failed bool, participatedShares map[int]bool, unexpectedPeers map[int]bool)
}

// New returns a new Tracker. The deleter deadliner must return well after analyser deadliner since duties of the same slot are often analysed together.
func New(analyser core.Deadliner, deleter core.Deadliner, peers []p2p.Peer, fromSlot int64) *Tracker {
	t := &Tracker{
		input:                 make(chan event),
		events:                make(map[core.Duty][]event),
		quit:                  make(chan struct{}),
		analyser:              analyser,
		deleter:               deleter,
		fromSlot:              fromSlot,
		failedDutyReporter:    newFailedDutyReporter(),
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
			if e.duty.Slot < t.fromSlot {
				continue // Ignore events before from slot.
			}
			if !t.deleter.Add(e.duty) || !t.analyser.Add(e.duty) {
				continue // Ignore expired or never expiring duties
			}

			t.events[e.duty] = append(t.events[e.duty], e)
		case duty := <-t.analyser.C():
			ctx := log.WithCtx(ctx, z.Any("duty", duty))

			// Analyse failed duties
			failed, failedComponent, failedMsg := analyseDutyFailed(duty, t.events)
			t.failedDutyReporter(ctx, duty, failed, failedComponent, failedMsg)

			// Analyse peer participation
			participatedShares, unexpectedShares := analyseParticipation(duty, t.events)
			t.participationReporter(ctx, duty, failed, participatedShares, unexpectedShares)
		case duty := <-t.deleter.C():
			delete(t.events, duty)
		}
	}
}

// dutyFailedComponent returns true if the duty failed. It also returns the component where the duty got stuck.
// If the duty didn't fail, it returns false and the zero component.
// It assumes that all the input events are for a single duty.
// If the input events slice is empty, it returns true the zero component.
func dutyFailedComponent(es []event) (bool, component) {
	events := make([]event, len(es))
	copy(events, es)

	// Sort in reverse order (see order above).
	sort.Slice(events, func(i, j int) bool {
		return events[i].component > events[j].component
	})

	if len(events) == 0 {
		return true, zero // Duty failed since no events.
	}

	c := events[0].component
	if c == sigAgg {
		return false, zero
	}

	return true, c + 1
}

// analyseDutyFailed detects if the given duty failed.
//
// It returns true if the duty failed as well as the component
// where the duty got stuck and a human friendly error message explaining why.
//
// It returns false if the duty didn't fail, i.e., the duty
// didn't get stuck and completed the sigAgg component.
func analyseDutyFailed(duty core.Duty, allEvents map[core.Duty][]event) (bool, component, string) {
	failed, comp := dutyFailedComponent(allEvents[duty])
	if !failed {
		return false, zero, ""
	}

	var msg string
	switch comp {
	case fetcher:
		return analyseFetcherFailed(duty, allEvents)
	case consensus:
		msg = msgConsensus
	case validatorAPI:
		msg = msgValidatorAPI
	case parSigDBInternal:
		msg = msgParSigDBInternal
	case parSigEx:
		msg = msgParSigEx
	case parSigDBThreshold:
		msg = msgParSigDBThreshold
	case sigAgg:
		msg = msgSigAgg
	case zero:
		msg = fmt.Sprintf("no events for %s duty", duty.String()) // This should never happen.
	default:
		msg = fmt.Sprintf("%s duty failed at %s", duty.String(), comp.String())
	}

	return true, comp, msg
}

// analyseFetcherFailed returns whether the duty that got stack in fetcher actually failed
// and the reason which might actually be due a pre-requisite duty that failed.
func analyseFetcherFailed(duty core.Duty, allEvents map[core.Duty][]event) (bool, component, string) {
	msg := msgFetcher

	// Proposer duties depend on randao duty, so check if that was why it failed.
	if duty.Type == core.DutyProposer || duty.Type == core.DutyBuilderProposer {
		// Proposer duties will fail if core.DutyRandao fails
		randaoFailed, randaoComp := dutyFailedComponent(allEvents[core.NewRandaoDuty(duty.Slot)])
		if randaoFailed {
			switch randaoComp {
			case parSigDBThreshold:
				msg = msgFetcherProposerFewRandaos
			case zero:
				msg = msgFetcherProposerZeroRandaos
			default:
				msg = msgFetcherProposerFailedRandao
			}
		}

		return true, fetcher, msg
	}

	// Duty aggregator depend on prepare aggregator duty, so check if that was why it failed.
	if duty.Type == core.DutyAggregator {
		// Aggregator duties will fail if core.DutyPrapareAggregator fails
		prepAggFailed, prepAggComp := dutyFailedComponent(allEvents[core.NewPrepareAggregatorDuty(duty.Slot)])
		if prepAggFailed {
			switch prepAggComp {
			case parSigDBThreshold:
				msg = msgFetcherAggregatorFewPrepares
			case zero:
				msg = msgFetcherAggregatorZeroPrepares
			default:
				msg = msgFetcherAggregatorFailedPrepare
			}

			return true, fetcher, msg
		}

		// Aggregator duties will fail if no attestation data in DutyDB
		attFailed, attComp := dutyFailedComponent(allEvents[core.NewAttesterDuty(duty.Slot)])
		if attFailed && attComp <= consensus {
			// Note we do not handle the edge case of the local peer failing to store attestation data
			// but the attester duty succeeding in any case due to external peer partial signatures.
			return true, fetcher, msgFetcherAggregatorNoAttData
		}

		// TODO(corver): We cannot distinguish between "no aggregators for slot"
		//  and "failed fetching aggregated attestation from BN".
		//
		// Assume no aggregators for slot as this is very common.
		return false, fetcher, ""
	}

	// Duty sync contribution depends on prepare sync contribution duty, so check if that was why it failed.
	if duty.Type == core.DutySyncContribution {
		// Sync contribution duties will fail if core.DutyPrepareSyncContribution fails.
		prepSyncConFailed, prepSyncConComp := dutyFailedComponent(allEvents[core.NewPrepareSyncContributionDuty(duty.Slot)])
		if prepSyncConFailed {
			switch prepSyncConComp {
			case parSigDBThreshold:
				msg = msgFetcherSyncContributionFewPrepares
			case zero:
				msg = msgFetcherSyncContributionZeroPrepares
			default:
				msg = msgFetcherSyncContributionFailedPrepare
			}

			return true, fetcher, msg
		}

		// Sync contribution duties will fail if no sync message in DutyDB.
		syncMsgFailed, syncMsgComp := dutyFailedComponent(allEvents[core.NewSyncMessageDuty(duty.Slot)])
		if syncMsgFailed && syncMsgComp <= consensus {
			// Note we do not handle the edge case of the local peer failing to store sync message
			// but the sync message duty succeeding in any case due to external peer partial signatures.
			return true, fetcher, msgFetcherSyncContributionNoSyncMsg
		}

		// TODO(dhruv): We cannot distinguish between "no sync committee aggregators for slot"
		//  and "failed fetching sync committee contribution from BN".
		//
		// Assume no aggregators for slot as this is very common.
		return false, fetcher, ""
	}

	return true, fetcher, msg
}

// newFailedDutyReporter returns failed duty reporter which instruments failed duties.
func newFailedDutyReporter() func(ctx context.Context, duty core.Duty, failed bool, component component, reason string) {
	var loggedNoSelections bool

	return func(ctx context.Context, duty core.Duty, failed bool, component component, reason string) {
		if !failed {
			return
		}

		if duty.Type == core.DutyAggregator && component == fetcher && reason == msgFetcherAggregatorZeroPrepares {
			if !loggedNoSelections {
				log.Warn(ctx, "Ignoring attestation aggregation failures since VCs do not seem to support beacon committee selection aggregation", nil)
			}
			loggedNoSelections = true

			return
		}

		if duty.Type == core.DutySyncContribution && component == fetcher && reason == msgFetcherSyncContributionZeroPrepares {
			if !loggedNoSelections {
				log.Warn(ctx, "Ignoring sync contribution failures since VCs do not seem to support sync committee selection aggregation", nil)
			}
			loggedNoSelections = true

			return
		}

		log.Warn(ctx, "Duty failed", nil,
			z.Any("component", component),
			z.Str("reason", reason))

		failedCounter.WithLabelValues(duty.Type.String(), component.String()).Inc()
	}
}

// analyseParticipation returns a set of share indexes of participated peers.
func analyseParticipation(duty core.Duty, allEvents map[core.Duty][]event) (map[int]bool, map[int]bool) {
	// Set of shareIdx of participated peers.
	resp := make(map[int]bool)
	unexpectedShares := make(map[int]bool)

	for _, e := range allEvents[duty] {
		// If we get a parSigDBInternal event, then the current node participated successfully.
		// If we get a parSigEx event, then the corresponding peer with e.shareIdx participated successfully.
		if e.component == parSigEx || e.component == parSigDBInternal {
			if !isParSigEventExpected(duty, e.pubkey, allEvents) {
				unexpectedShares[e.shareIdx] = true
				continue
			}

			resp[e.shareIdx] = true
		}
	}

	return resp, unexpectedShares
}

// isParSigEventExpected returns true if a partial signature event is expected for the given duty and pubkey.
// It basically checks if the duty (or an associated duty) was scheduled.
func isParSigEventExpected(duty core.Duty, pubkey core.PubKey, allEvents map[core.Duty][]event) bool {
	// Cannot validate validatorAPI triggered duties that are not linked to locally scheduled duties.
	if !canSchedule(duty.Type) {
		return true
	}

	// scheduled returns true if the provided duty type was scheduled for the above slot and pubkey.
	scheduled := func(typ core.DutyType) bool {
		for _, e := range allEvents[core.Duty{Slot: duty.Slot, Type: typ}] {
			if e.component == scheduler && e.pubkey == pubkey {
				return true
			}
		}

		return false
	}

	// For DutyRandao, check that if DutyProposer or DutyBuilderProposer was scheduled.
	if duty.Type == core.DutyRandao {
		return scheduled(core.DutyProposer) || scheduled(core.DutyBuilderProposer)
	}

	// For DutyPrepareAggregator, check that if DutyAttester was scheduled.
	if duty.Type == core.DutyPrepareAggregator {
		return scheduled(core.DutyAttester)
	}

	// For DutyPrepareSyncContribution, check that if DutySyncContribution was scheduled.
	if duty.Type == core.DutyPrepareSyncContribution {
		return scheduled(core.DutySyncContribution)
	}

	// For all other duties check if the type itself was scheduled.
	return scheduled(duty.Type)
}

// canSchedule returns true if the given duty type can be scheduled by scheduler.
func canSchedule(duty core.DutyType) bool {
	return !(duty == core.DutyExit || duty == core.DutyBuilderRegistration || duty == core.DutySyncMessage)
}

// newParticipationReporter returns a new participation reporter function which logs and instruments peer participation
// and unexpectedPeers.
func newParticipationReporter(peers []p2p.Peer) func(context.Context, core.Duty, bool, map[int]bool, map[int]bool) {
	// prevAbsent is the set of peers who didn't participate in the last duty per type.
	prevAbsent := make(map[core.DutyType][]string)

	return func(ctx context.Context, duty core.Duty, failed bool, participatedShares map[int]bool, unexpectedShares map[int]bool) {
		if len(participatedShares) == 0 && !failed {
			// Ignore participation metrics and log for noop duties (like DutyAggregator)
			return
		}

		var absentPeers []string
		for _, peer := range peers {
			if participatedShares[peer.ShareIdx()] {
				participationGauge.WithLabelValues(duty.Type.String(), peer.Name).Set(1)
				participationCounter.WithLabelValues(duty.Type.String(), peer.Name).Inc()
			} else if unexpectedShares[peer.ShareIdx()] {
				log.Warn(ctx, "Unexpected event found", nil, z.Str("peer", peer.Name), z.Str("duty", duty.String()))
				unexpectedEventsCounter.WithLabelValues(peer.Name).Inc()
			} else {
				absentPeers = append(absentPeers, peer.Name)
				participationGauge.WithLabelValues(duty.Type.String(), peer.Name).Set(0)
			}
		}

		if fmt.Sprint(prevAbsent[duty.Type]) != fmt.Sprint(absentPeers) {
			if len(absentPeers) == 0 {
				log.Info(ctx, "All peers participated in duty")
			} else if len(absentPeers) == len(peers) {
				log.Info(ctx, "No peers participated in duty")
			} else {
				log.Info(ctx, "Not all peers participated in duty", z.Any("absent", absentPeers))
			}
		}

		prevAbsent[duty.Type] = absentPeers
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
