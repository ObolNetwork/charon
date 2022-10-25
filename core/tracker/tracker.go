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
	"encoding/json"
	"fmt"
	"sort"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/p2p"
)

// Steps arranged in the order they are triggered in the core workflow.
const (
	zero              step = iota
	scheduler              // Duty scheduled with definition
	fetcher                // Duty data fetched
	consensus              // Duty data consensus reached
	validatorAPI           // Partial signed data from local VC submitted to vapi
	parSigDBInternal       // Partial signed data from local VC stored in parsigdb
	parSigEx               // Partial signed data from other VC received via parsigex
	parSigDBThreshold      // Partial signed data threshold reached; emitted from parsigdb
	sigAgg                 // Partial signed data aggregated; emitted from sigagg
	sentinel
)

var stepLabels = map[step]string{
	zero:              "unknown",
	scheduler:         "scheduler",
	fetcher:           "fetcher",
	consensus:         "consensus",
	validatorAPI:      "validator_api",
	parSigDBInternal:  "parsig_db_local",
	parSigEx:          "parsig_exchange",
	parSigDBThreshold: "parsig_db_threshold",
	sigAgg:            "sig_aggregation",
}

// step in the core workflow.
type step int

func (s step) String() string {
	return stepLabels[s]
}

// These constants are used for improving messages for why a duty failed.
const (
	// msgFetcher indicates a duty failed in the fetcher step when it failed
	// to fetch the required data from the beacon node API. This indicates a problem with
	// the upstream beacon node.
	msgFetcher = "couldn't fetch duty data from the beacon node"

	// msgFetcherAggregatorNoAttData indicates an attestation aggregation duty failed in
	// the fetcher step since it couldn't fetch the prerequisite attestation data. This
	// indicates the associated attestation duty failed to obtain a cluster agreed upon value.
	msgFetcherAggregatorNoAttData = "couldn't aggregate attestation due to failed attester duty"

	// msgFetcherAggregatorFewPrepares indicates an attestation aggregation duty failed in
	// the fetcher step since it couldn't fetch the prerequisite aggregated beacon committee selections.
	// This indicates the associated prepare aggregation duty failed due to insufficient partial beacon committee selections
	// submitted by the cluster validator clients.
	msgFetcherAggregatorFewPrepares = "couldn't aggregate attestation due to insufficient partial beacon committee selections"

	// msgFetcherAggregatorZeroPrepares indicates an attestation aggregation duty failed in
	// the fetcher step since it couldn't fetch the prerequisite aggregated beacon committee selections.
	// This indicates the associated prepare aggregation duty failed due to no partial beacon committee selections
	// submitted by the cluster validator clients.
	msgFetcherAggregatorZeroPrepares = "couldn't aggregate attestation due to zero partial beacon committee selections"

	// msgFetcherAggregatorFailedPrepare indicates an attestation aggregation duty failed in
	// the fetcher step since it couldn't fetch the prerequisite aggregated beacon committee selections.
	// This indicates the associated prepare aggregation duty failed.
	msgFetcherAggregatorFailedPrepare = "couldn't aggregate attestation due to failed prepare aggregator duty"

	// msgFetcherProposerFewRandaos indicates a block proposer duty failed in
	// the fetcher step since it couldn't fetch the prerequisite aggregated RANDAO.
	// This indicates the associated randao duty failed due to insufficient partial randao signatures
	// submitted by the cluster validator clients.
	msgFetcherProposerFewRandaos = "couldn't propose block due to insufficient partial randao signatures"

	// msgFetcherProposerZeroRandaos indicates a block proposer duty failed in
	// the fetcher step since it couldn't fetch the prerequisite aggregated RANDAO.
	// This indicates the associated randao duty failed due to no partial randao signatures
	// submitted by the cluster validator clients.
	msgFetcherProposerZeroRandaos = "couldn't propose block due to zero partial randao signatures"

	// msgFetcherProposerZeroRandaos indicates a block proposer duty failed in
	// the fetcher step since it couldn't fetch the prerequisite aggregated RANDAO.
	// This indicates the associated randao duty failed.
	msgFetcherProposerFailedRandao = "couldn't propose block due to failed randao duty"

	// msgFetcherSyncContributionNoSyncMsg indicates a sync contribution duty failed in
	// the fetcher step since it couldn't fetch the prerequisite sync message. This
	// indicates the associated sync message duty failed to obtain a cluster agreed upon value.
	msgFetcherSyncContributionNoSyncMsg = "couldn't fetch sync contribution due to failed sync message duty"

	// msgFetcherSyncContributionFewPrepares indicates a sync contribution duty failed in
	// the fetcher step since it couldn't fetch the prerequisite aggregated sync contribution selections.
	// This indicates the associated prepare sync contribution duty failed due to insufficient partial sync contribution selections
	// submitted by the cluster validator clients.
	msgFetcherSyncContributionFewPrepares = "couldn't fetch sync contribution due to insufficient partial sync contribution selections"

	// msgFetcherSyncContributionZeroPrepares indicates a sync contribution duty failed in
	// the fetcher step since it couldn't fetch the prerequisite aggregated sync contribution selections.
	// This indicates the associated prepare sync contribution duty failed due to no partial sync contribution selections
	// submitted by the cluster validator clients.
	msgFetcherSyncContributionZeroPrepares = "couldn't fetch sync contribution due to zero partial sync contribution selections"

	// msgFetcherSyncContributionFailedPrepare indicates a sync contribution duty failed in
	// the fetcher step since it couldn't fetch the prerequisite aggregated sync contribution selections.
	// This indicates the associated prepare sync contribution duty failed.
	msgFetcherSyncContributionFailedPrepare = "couldn't fetch sync contribution due to failed prepare sync contribution duty"

	// msgConsensus indicates a duty failed in consensus step.
	// This could indicate that insufficient honest peers participated in consensus or p2p network
	// connection problems.
	msgConsensus = "consensus algorithm didn't complete"

	// msgValidatorAPI indicates that partial signature we never submitted by the local
	// validator client. This could indicate that the local validator client is offline,
	// or has connection problems with charon, or has some other problem. See validator client
	// logs for more details.
	msgValidatorAPI = "signed duty not submitted by local validator client"

	// msgParSigDBInternal indicates a bug in the partial signature database as it is unexpected.
	// Note this may happen due to expiry race.
	msgParSigDBInternal = "partial signature database didn't trigger partial signature exchange"

	// msgParSigEx indicates that no partial signature for the duty was received from any peer.
	// This indicates all peers are offline or p2p network connection problems.
	msgParSigEx = "no partial signatures received from peers"

	// msgParSigDBInsufficient indicates that insufficient partial signatures for the duty was received from peers.
	// This indicates problems with peers or p2p network connection problems.
	msgParSigDBInsufficient = "insufficient partial signatures received, minimum required threshold not reached"

	// msgParSigDBInconsistentSync indicates that partial signed data for the sync committee duty were inconsistent.
	// This is known limitation in this version of charon.
	msgParSigDBInconsistentSync = "known limitation: inconsistent sync committee signatures received"

	// msgParSigDBInconsistent indicates that partial signed data for the duty were inconsistent.
	// This indicates a bug in charon as it is unexpected (for non-sync-committee-duties).
	msgParSigDBInconsistent = "bug: inconsistent partial signatures received"

	// msgSigAgg indicates that BLS threshold aggregation of sufficient partial signatures failed. This
	// indicates inconsistent signed data. This indicates a bug in charon as it is unexpected.
	msgSigAgg = "bug: threshold aggregation of partial signatures failed due to inconsistent signed data"
)

// parsigsByMsg.
type parsigsByMsg map[string][]int

// event represents an event emitted by a core workflow step.
type event struct {
	duty   core.Duty
	step   step
	pubkey core.PubKey

	// parSig is an optional field only set by validatorAPI, parSigDBInternal and parSigEx events.
	parSig *core.ParSignedData
}

// Tracker represents the step that listens to events from core workflow steps.
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

	// parSigReporter instruments partial signature data inconsistencies.
	parSigReporter func(ctx context.Context, duty core.Duty, parsigMsgs parsigsByMsg)

	// failedDutyReporter instruments duty failures.
	failedDutyReporter func(ctx context.Context, duty core.Duty, failed bool, step step, reason string)

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
		parSigReporter:        parSigReporter,
		failedDutyReporter:    newFailedDutyReporter(),
		participationReporter: newParticipationReporter(peers),
	}

	return t
}

// Run blocks and registers events from each step in tracker's input channel.
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

			parsigs := analyseParSigs(t.events[duty])
			t.parSigReporter(ctx, duty, parsigs)

			// Analyse failed duties
			failed, failedStep, failedMsg := analyseDutyFailed(duty, t.events, parsigs)
			t.failedDutyReporter(ctx, duty, failed, failedStep, failedMsg)

			// Analyse peer participation
			participatedShares, unexpectedShares := analyseParticipation(duty, t.events)
			t.participationReporter(ctx, duty, failed, participatedShares, unexpectedShares)
		case duty := <-t.deleter.C():
			delete(t.events, duty)
		}
	}
}

// dutyFailedStep returns true if the duty failed. It also returns the step where the duty got stuck.
// If the duty didn't fail, it returns false and the zero step.
// It assumes that all the input events are for a single duty.
// If the input events slice is empty, it returns true and the zero step.
func dutyFailedStep(es []event) (bool, step) {
	if len(es) == 0 {
		return true, zero // Duty failed since no events.
	}

	// Copy and sort in reverse order (see step order above).
	clone := append([]event(nil), es...)
	sort.Slice(clone, func(i, j int) bool {
		return clone[i].step > clone[j].step
	})

	step := clone[0].step
	if step == sigAgg {
		return false, zero
	}

	return true, step + 1
}

// analyseDutyFailed detects if the given duty failed.
//
// It returns true if the duty failed as well as the step
// where the duty got stuck and a human friendly error message explaining why.
//
// It returns false if the duty didn't fail, i.e., the duty
// didn't get stuck and completed the sigAgg step.
func analyseDutyFailed(duty core.Duty, allEvents map[core.Duty][]event, parsigMsgs parsigsByMsg) (bool, step, string) {
	failed, step := dutyFailedStep(allEvents[duty])
	if !failed {
		return false, zero, ""
	}

	var msg string
	switch step {
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
		if len(parsigMsgs) <= 1 {
			msg = msgParSigDBInsufficient
		} else {
			msg = msgParSigDBInconsistent
			if expectInconsistentParSigs(duty.Type) {
				msg = msgParSigDBInconsistentSync
			}
		}

		return true, parSigDBThreshold, msg
	case sigAgg:
		msg = msgSigAgg
	case zero:
		msg = fmt.Sprintf("no events for %s duty", duty.String()) // This should never happen.
	default:
		msg = fmt.Sprintf("%s duty failed at %s", duty.String(), step.String())
	}

	return true, step, msg
}

// analyseParSigs returns a mapping of partial signed data messages by peers (share index).
func analyseParSigs(events []event) parsigsByMsg {
	var (
		dedup = make(map[int]bool)
		datas = make(map[string][]int)
	)

	for _, e := range events {
		if e.parSig == nil {
			continue
		}
		if dedup[e.parSig.ShareIdx] {
			continue
		}
		dedup[e.parSig.ShareIdx] = true

		// Clear signature to get unsigned data
		noSig, err := e.parSig.SetSignature(nil)
		if err != nil {
			log.Warn(context.Background(), "Clear partial signature", err)
			continue // Just log and ignore as this is highly unlikely and non-critical code.
		}
		data, err := json.Marshal(noSig)
		if err != nil {
			log.Warn(context.Background(), "Marshal parsig", err)
			continue // Just log and ignore as this is highly unlikely and non-critical code.
		}

		datas[string(data)] = append(datas[string(data)], e.parSig.ShareIdx)
	}

	return datas
}

// analyseFetcherFailed returns whether the duty that got stack in fetcher actually failed
// and the reason which might actually be due a pre-requisite duty that failed.
func analyseFetcherFailed(duty core.Duty, allEvents map[core.Duty][]event) (bool, step, string) {
	msg := msgFetcher

	// Proposer duties depend on randao duty, so check if that was why it failed.
	if duty.Type == core.DutyProposer || duty.Type == core.DutyBuilderProposer {
		// Proposer duties will fail if core.DutyRandao fails
		randaoFailed, randaoStep := dutyFailedStep(allEvents[core.NewRandaoDuty(duty.Slot)])
		if randaoFailed {
			switch randaoStep {
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
		prepAggFailed, prepAggStep := dutyFailedStep(allEvents[core.NewPrepareAggregatorDuty(duty.Slot)])
		if prepAggFailed {
			switch prepAggStep {
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
		attFailed, attStep := dutyFailedStep(allEvents[core.NewAttesterDuty(duty.Slot)])
		if attFailed && attStep <= consensus {
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
		prepSyncConFailed, prepSyncConStep := dutyFailedStep(allEvents[core.NewPrepareSyncContributionDuty(duty.Slot)])
		if prepSyncConFailed {
			switch prepSyncConStep {
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
		syncMsgFailed, syncMsgStep := dutyFailedStep(allEvents[core.NewSyncMessageDuty(duty.Slot)])
		if syncMsgFailed && syncMsgStep <= consensus {
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
func newFailedDutyReporter() func(ctx context.Context, duty core.Duty, failed bool, step step, reason string) {
	var loggedNoSelections bool

	return func(ctx context.Context, duty core.Duty, failed bool, step step, reason string) {
		counter := failedCounter.WithLabelValues(duty.Type.String())
		counter.Add(0) // Zero the metric so first failure shows in grafana.

		if !failed {
			return
		}

		if duty.Type == core.DutyAggregator && step == fetcher && reason == msgFetcherAggregatorZeroPrepares {
			if !loggedNoSelections {
				log.Warn(ctx, "Ignoring attestation aggregation failures since VCs do not seem to support beacon committee selection aggregation", nil)
			}
			loggedNoSelections = true

			return
		}

		if duty.Type == core.DutySyncContribution && step == fetcher && reason == msgFetcherSyncContributionZeroPrepares {
			if !loggedNoSelections {
				log.Warn(ctx, "Ignoring sync contribution failures since VCs do not seem to support sync committee selection aggregation", nil)
			}
			loggedNoSelections = true

			return
		}

		log.Warn(ctx, "Duty failed", nil,
			z.Any("step", step),
			z.Str("reason", reason))

		counter.Inc()
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
		if e.step == parSigEx || e.step == parSigDBInternal {
			if !isParSigEventExpected(duty, e.pubkey, allEvents) {
				unexpectedShares[e.parSig.ShareIdx] = true
				continue
			}

			resp[e.parSig.ShareIdx] = true
		}
	}

	return resp, unexpectedShares
}

// isParSigEventExpected returns true if a partial signature event is expected for the given duty and pubkey.
// It basically checks if the duty (or an associated duty) was scheduled.
func isParSigEventExpected(duty core.Duty, pubkey core.PubKey, allEvents map[core.Duty][]event) bool {
	// Cannot validate validatorAPI triggered duties that are not linked to locally scheduled duties.
	if duty.Type == core.DutyExit || duty.Type == core.DutyBuilderRegistration || duty.Type == core.DutySyncMessage {
		return true
	}

	// scheduled returns true if the provided duty type was scheduled for the above slot and pubkey.
	scheduled := func(typ core.DutyType) bool {
		for _, e := range allEvents[core.Duty{Slot: duty.Slot, Type: typ}] {
			if e.step == scheduler && e.pubkey == pubkey {
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

	// For DutyPrepareSyncContribution and DutySyncMessage, check that if DutySyncContribution was scheduled.
	if duty.Type == core.DutyPrepareSyncContribution { // TODO(corver): Add sync message here once we schedule sync contribution.
		return scheduled(core.DutySyncContribution)
	}

	// For all other duties check if the type itself was scheduled.
	return scheduled(duty.Type)
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

// SchedulerEvent inputs event from core.Scheduler step.
func (t *Tracker) SchedulerEvent(ctx context.Context, duty core.Duty, defSet core.DutyDefinitionSet) error {
	if ctx.Err() != nil {
		return nil //nolint:nilerr // Ignore event if expired.
	}
	for pubkey := range defSet {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.quit:
			return nil
		case t.input <- event{
			duty:   duty,
			step:   scheduler,
			pubkey: pubkey,
		}:
		}
	}

	return nil
}

// FetcherEvent inputs event from core.Fetcher step.
func (t *Tracker) FetcherEvent(ctx context.Context, duty core.Duty, data core.UnsignedDataSet) error {
	if ctx.Err() != nil {
		return nil //nolint:nilerr // Ignore event if expired.
	}
	for pubkey := range data {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.quit:
			return nil
		case t.input <- event{
			duty:   duty,
			step:   fetcher,
			pubkey: pubkey,
		}:
		}
	}

	return nil
}

// ConsensusEvent inputs event from core.Consensus step.
func (t *Tracker) ConsensusEvent(ctx context.Context, duty core.Duty, data core.UnsignedDataSet) error {
	if ctx.Err() != nil {
		return nil //nolint:nilerr // Ignore event if expired.
	}
	for pubkey := range data {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.quit:
			return nil
		case t.input <- event{
			duty:   duty,
			step:   consensus,
			pubkey: pubkey,
		}:
		}
	}

	return nil
}

// ValidatorAPIEvent inputs events from core.ValidatorAPI step.
func (t *Tracker) ValidatorAPIEvent(ctx context.Context, duty core.Duty, data core.ParSignedDataSet) error {
	if ctx.Err() != nil {
		return nil //nolint:nilerr // Ignore event if expired.
	}
	for pubkey, parSig := range data {
		parSig := parSig // Copy loop iteration values
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.quit:
			return nil
		case t.input <- event{
			duty:   duty,
			step:   validatorAPI,
			pubkey: pubkey,
			parSig: &parSig,
		}:
		}
	}

	return nil
}

// ParSigExEvent inputs event from core.ParSigEx step event for other VC submitted parsigs.
func (t *Tracker) ParSigExEvent(ctx context.Context, duty core.Duty, data core.ParSignedDataSet) error {
	if ctx.Err() != nil {
		return nil //nolint:nilerr // Ignore event if expired.
	}
	for pubkey, parSig := range data {
		parSig := parSig // Copy loop iteration values
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.quit:
			return nil
		case t.input <- event{
			duty:   duty,
			step:   parSigEx,
			pubkey: pubkey,
			parSig: &parSig,
		}:
		}
	}

	return nil
}

// ParSigDBInternalEvent inputs events from core.ParSigDB step event for local VC submitted parsigs.
func (t *Tracker) ParSigDBInternalEvent(ctx context.Context, duty core.Duty, data core.ParSignedDataSet) error {
	if ctx.Err() != nil {
		return nil //nolint:nilerr // Ignore event if expired.
	}
	for pubkey, parSig := range data {
		parSig := parSig // Copy loop iteration values
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.quit:
			return nil
		case t.input <- event{
			duty:   duty,
			step:   parSigDBInternal,
			pubkey: pubkey,
			parSig: &parSig,
		}:
		}
	}

	return nil
}

// ParSigDBThresholdEvent inputs event from core.ParSigDB step for threshold emitted parsigs.
func (t *Tracker) ParSigDBThresholdEvent(ctx context.Context, duty core.Duty, pubkey core.PubKey, _ []core.ParSignedData) error {
	if ctx.Err() != nil {
		return nil //nolint:nilerr // Ignore event if expired.
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.quit:
		return nil
	case t.input <- event{
		duty:   duty,
		step:   parSigDBThreshold,
		pubkey: pubkey,
	}:
	}

	return nil
}

// SigAggEvent inputs event from core.SigAgg step.
func (t *Tracker) SigAggEvent(ctx context.Context, duty core.Duty, pubkey core.PubKey, _ core.SignedData) error {
	if ctx.Err() != nil {
		return nil //nolint:nilerr // Ignore event if expired.
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.quit:
		return nil
	case t.input <- event{
		duty:   duty,
		step:   sigAgg,
		pubkey: pubkey,
	}:
	}

	return nil
}

func parSigReporter(ctx context.Context, duty core.Duty, parsigMsgs parsigsByMsg) {
	if len(parsigMsgs) <= 1 {
		return // Nothing to report.
	}

	inconsistentCounter.WithLabelValues(duty.Type.String()).Inc()

	if expectInconsistentParSigs(duty.Type) {
		log.Debug(ctx, "Inconsistent sync committee partial signed data",
			z.Any("data", parsigMsgs))
	} else {
		log.Warn(ctx, "Inconsistent partial signed data", nil,
			z.Any("data", parsigMsgs))
	}
}

// expectInconsistentParSigs returns true if the duty type is expected to sometimes
// produce inconsistent partial signed data.
func expectInconsistentParSigs(duty core.DutyType) bool {
	return duty == core.DutySyncMessage || duty == core.DutySyncContribution
}
