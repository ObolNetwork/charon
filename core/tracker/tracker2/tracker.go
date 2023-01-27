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

package tracker2

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	eth2http "github.com/attestantio/go-eth2-client/http"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/p2p"
)

// Steps arranged in the order they are triggered in the core workflow.
const (
	zero              step = iota
	fetcher                // Duty data fetched
	consensus              // Duty data consensus reached
	dutyDB                 // Duty data stored in DutyDB
	validatorAPI           // Partial signed data from local VC submitted to vapi
	parSigDBInternal       // Partial signed data from local VC stored in parsigdb
	parSigEx               // Partial signed data from other VC received via parsigex
	parSigDBExternal       // Partial signed data from other VC stored in parsigdb
	parSigDBThreshold      // Partial signed data threshold reached; emitted from parsigdb
	sigAgg                 // Partial signed data aggregated; emitted from sigagg
	bcast                  // Aggregated data submitted to beacon node
	sentinel
)

var stepLabels = map[step]string{
	zero:              "unknown",
	fetcher:           "fetcher",
	consensus:         "consensus",
	dutyDB:            "duty_db",
	validatorAPI:      "validator_api",
	parSigDBInternal:  "parsig_db_local",
	parSigEx:          "parsig_exchange",
	parSigDBExternal:  "parsig_db_external",
	parSigDBThreshold: "parsig_db_threshold",
	sigAgg:            "sig_aggregation",
	bcast:             "bcast",
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

	// msgFetcherAggregatorNoExternalPrepares indicates an attestation aggregation duty failed in
	// the fetcher step since it couldn't fetch the prerequisite aggregated beacon committee selections.
	// This indicates the associated prepare aggregation duty failed due to no partial beacon committee selections received from peers.
	msgFetcherAggregatorNoExternalPrepares = "couldn't aggregate attestation due to no partial beacon committee selections received from peers"

	// msgFetcherAggregatorFailedSigAggPrepare indicates an attestation aggregation duty failed in
	// the fetcher step since it couldn't fetch the prerequisite aggregated beacon committee selections.
	// This indicates the associated prepare aggregation duty failed due to failure of threshold signature aggregation.
	// This indicates a bug in charon as it is unexpected.
	msgFetcherAggregatorFailedSigAggPrepare = "couldn't aggregate attestation due to no aggregated beacon committee selection, this is unexpected"

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

	// msgFetcherProposerNoExternalRandaos indicates a block proposer duty failed in
	// the fetcher step since it couldn't fetch the prerequisite aggregated RANDAO.
	// This indicates the associated randao duty failed due to no partial randao signatures received from peers.
	msgFetcherProposerNoExternalRandaos = "couldn't propose block due to no partial randao signatures received from peers"

	// msgFetcherProposerFailedSigAggRandao indicates a block proposer duty failed in
	// the fetcher step since it couldn't fetch the prerequisite aggregated RANDAO.
	// This indicates the associated randao duty failed due to failure of threshold signature aggregation.
	// This indicates a bug in charon as it is unexpected.
	msgFetcherProposerFailedSigAggRandao = "couldn't propose block due to no aggregated randao signature, this is unexpected"

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

	// msgFetcherSyncContributionNoExternalPrepares indicates a sync contribution duty failed in
	// the fetcher step since it couldn't fetch the prerequisite aggregated sync contribution selections.
	// This indicates the associated prepare sync contribution duty failed due to no partial sync contribution selections received from peers.
	msgFetcherSyncContributionNoExternalPrepares = "couldn't fetch sync contribution due to no partial sync contribution selections received from peers"

	// msgFetcherSyncContributionFailedSigAggPrepare indicates a sync contribution duty failed in
	// the fetcher step since it couldn't fetch the prerequisite aggregated sync contribution selections.
	// This indicates the associated prepare sync contribution duty failed due to failure of threshold signature aggregation.
	// This indicates a bug in charon as it is unexpected.
	msgFetcherSyncContributionFailedSigAggPrepare = "couldn't fetch sync contribution due to no aggregated sync contribution selection, this is unexpected"

	// msgFetcherUnknownError indicates duty failed in fetcher step with some unknown error.
	// This indicates a bug in charon as it is unexpected.
	msgFetcherUnknownError = "couldn't fetch due to unknown error"

	// msgConsensus indicates a duty failed in consensus step.
	// This could indicate that insufficient honest peers participated in consensus or p2p network
	// connection problems.
	msgConsensus = "consensus algorithm didn't complete"

	// msgDutyDB indicates a bug in the DutyDB database as it is unexpected.
	msgDutyDB = "bug: failed to store duty data in DutyDB"

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

	// msgParSigDBExternal indicates a bug in the partial signature database as it is unexpected.
	msgParSigDBExternal = "bug: failed to store external partial signatures in parsigdb"

	// msgSigAgg indicates that BLS threshold aggregation of sufficient partial signatures failed. This
	// indicates inconsistent signed data. This indicates a bug in charon as it is unexpected.
	msgSigAgg = "bug: threshold aggregation of partial signatures failed due to inconsistent signed data"

	// msgBcast indicates that beacon node returned an error while submitting aggregated duty signature to beacon node.
	msgBcast = "failed to broadcast duty to beacon node"
)

// parsigsByMsg contains partial signatures grouped by message root grouped by pubkey.
type parsigsByMsg map[core.PubKey]map[[32]byte][]core.ParSignedData

// MsgRootsConsistent returns true if the all partial signatures have consistent message roots.
func (m parsigsByMsg) MsgRootsConsistent() bool {
	for _, inner := range m {
		if len(inner) > 1 {
			return false
		}
	}

	return true
}

// event represents an event emitted by a core workflow step.
type event struct {
	duty    core.Duty
	step    step
	pubkey  core.PubKey
	stepErr error

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
		parSigReporter:        reportParSigs,
		failedDutyReporter:    newFailedDutyReporter(),
		participationReporter: newParticipationReporter(peers),
	}

	return t
}

// Run blocks and registers events from each step in tracker's input channel.
// It also analyses and reports the duties whose deadline gets crossed.
func (t *Tracker) Run(ctx context.Context) error {
	ctx = log.WithTopic(ctx, "tracker2")
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

			parsigs := analyseParSigs(ctx, t.events[duty])
			t.parSigReporter(ctx, duty, parsigs)

			// Analyse failed duties
			failed, failedStep, failedMsg := analyseDutyFailed(duty, t.events, parsigs.MsgRootsConsistent())
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
func dutyFailedStep(es []event) (bool, step, error) {
	if len(es) == 0 {
		return true, zero, nil // Duty failed since no events.
	}

	// Copy and sort in ascending order of steps (see step order above).
	clone := append([]event(nil), es...)

	// SliceStable is needed to keep same elements in the original order which means multiple events of the same step
	// with at least one non-error event will have error events followed by non-error events in the sorted slice as
	// retryer doesn't retry after successful attempt.
	sort.SliceStable(clone, func(i, j int) bool {
		return clone[i].step < clone[j].step
	})

	lastEvent := clone[len(clone)-1]

	// No failed step.
	if lastEvent.step == bcast && lastEvent.stepErr == nil {
		return false, zero, nil
	}

	// Failed in last event.
	if lastEvent.stepErr != nil {
		return true, lastEvent.step, lastEvent.stepErr
	}

	return true, lastEvent.step + 1, nil
}

// analyseDutyFailed detects if the given duty failed.
//
// It returns true if the duty failed as well as the step
// where the duty got stuck and a human friendly error message explaining why.
//
// It returns false if the duty didn't fail, i.e., the duty
// didn't get stuck and completed the bcast step.
func analyseDutyFailed(duty core.Duty, allEvents map[core.Duty][]event, msgRootConsistent bool) (failed bool, failedStep step, failureMsg string) {
	failed, step, err := dutyFailedStep(allEvents[duty])
	if !failed {
		return false, zero, ""
	}

	defer func() {
		if err != nil {
			failureMsg = fmt.Sprintf("%s with error: %s", failureMsg, err.Error())
		}
	}()

	var msg string
	switch step {
	case fetcher:
		msg = analyseFetcherFailed(duty, allEvents, err)
	case consensus:
		return analyseConsensusFailed(duty, err)
	case dutyDB:
		msg = msgDutyDB
	case validatorAPI:
		msg = msgValidatorAPI
	case parSigDBInternal:
		msg = msgParSigDBInternal
	case parSigEx:
		msg = msgParSigEx
	case parSigDBExternal:
		msg = msgParSigDBExternal
	case parSigDBThreshold:
		if msgRootConsistent {
			msg = msgParSigDBInsufficient
		} else {
			msg = msgParSigDBInconsistent
			if expectInconsistentParSigs(duty.Type) {
				msg = msgParSigDBInconsistentSync
			}
		}
	case sigAgg:
		msg = msgSigAgg
	case bcast:
		msg = msgBcast
	case zero:
		msg = fmt.Sprintf("no events for %s duty", duty.String()) // This should never happen.
	default:
		msg = fmt.Sprintf("%s duty failed at %s", duty.String(), step.String())
	}

	return failed, step, msg
}

// analyseFetcherFailed returns whether the duty that got stuck in fetcher actually failed
// and the reason which might actually be due a pre-requisite duty that failed.
func analyseFetcherFailed(duty core.Duty, allEvents map[core.Duty][]event, fetchErr error) string {
	// Check for beacon api errors.
	var eth2Error eth2http.Error
	if errors.As(fetchErr, &eth2Error) {
		return msgFetcher
	}

	// Proposer duties depend on randao duty, so check if that was why it failed.
	if duty.Type == core.DutyProposer || duty.Type == core.DutyBuilderProposer {
		// Proposer duties will fail if core.DutyRandao fails.
		// Ignoring error as it will be handled in DutyRandao analysis.
		randaoFailed, randaoStep, _ := dutyFailedStep(allEvents[core.NewRandaoDuty(duty.Slot)])
		if randaoFailed {
			switch randaoStep {
			case parSigDBThreshold:
				return msgFetcherProposerFewRandaos
			case parSigEx, parSigDBExternal:
				return msgFetcherProposerNoExternalRandaos
			case sigAgg:
				return msgFetcherProposerFailedSigAggRandao
			case zero:
				return msgFetcherProposerZeroRandaos
			default:
				return msgFetcherProposerFailedRandao
			}
		}
	}

	// Duty aggregator depend on prepare aggregator duty, so check if that was why it failed.
	if duty.Type == core.DutyAggregator {
		// Aggregator duties will fail if core.DutyPrepareAggregator fails.
		// Ignoring error as it will be handled in DutyPrepareAggregator duty analysis.
		prepAggFailed, prepAggStep, _ := dutyFailedStep(allEvents[core.NewPrepareAggregatorDuty(duty.Slot)])
		if prepAggFailed {
			switch prepAggStep {
			case parSigDBThreshold:
				return msgFetcherAggregatorFewPrepares
			case parSigEx, parSigDBExternal:
				return msgFetcherAggregatorNoExternalPrepares
			case sigAgg:
				return msgFetcherAggregatorFailedSigAggPrepare
			case zero:
				return msgFetcherAggregatorZeroPrepares
			default:
				return msgFetcherAggregatorFailedPrepare
			}
		}

		// Aggregator duties will fail if no attestation data in DutyDB.
		// Ignoring error as it will be handled in DutyAttester analysis.
		attFailed, attStep, _ := dutyFailedStep(allEvents[core.NewAttesterDuty(duty.Slot)])
		if attFailed && attStep <= dutyDB {
			return msgFetcherAggregatorNoAttData
		}
	}

	// Duty sync contribution depends on prepare sync contribution duty, so check if that was why it failed.
	if duty.Type == core.DutySyncContribution {
		// Sync contribution duties will fail if core.DutyPrepareSyncContribution fails.
		// Ignoring error as it will be handled in DutyPrepareSyncContribution analysis.
		prepSyncConFailed, prepSyncConStep, _ := dutyFailedStep(allEvents[core.NewPrepareSyncContributionDuty(duty.Slot)])
		if prepSyncConFailed {
			switch prepSyncConStep {
			case parSigDBThreshold:
				return msgFetcherSyncContributionFewPrepares
			case parSigEx, parSigDBExternal:
				return msgFetcherSyncContributionNoExternalPrepares
			case sigAgg:
				return msgFetcherSyncContributionFailedSigAggPrepare
			case zero:
				return msgFetcherSyncContributionZeroPrepares
			default:
				return msgFetcherSyncContributionFailedPrepare
			}
		}

		// Sync contribution duties will fail if no sync message in AggSigDB.
		// Ignoring error as it will be handled in DutySyncMessage analysis.
		syncMsgFailed, syncMsgStep, _ := dutyFailedStep(allEvents[core.NewSyncMessageDuty(duty.Slot)])
		if syncMsgFailed && syncMsgStep <= sigAgg {
			return msgFetcherSyncContributionNoSyncMsg
		}
	}

	return msgFetcherUnknownError
}

// analyseConsensusFailed returns whether the duty that got stuck in consensus got failed
// because of error in consensus component.
func analyseConsensusFailed(duty core.Duty, consensusErr error) (bool, step, string) {
	// No aggregators or sync committee contributors found in this slot.
	// Fetcher sends an event with nil error in this case.
	if consensusErr == nil && (duty.Type == core.DutyAggregator || duty.Type == core.DutySyncContribution) {
		return false, fetcher, ""
	}

	return true, consensus, msgConsensus
}

// analyseParSigs returns a mapping of partial signed data messages by peers (share index) by validator (pubkey).
func analyseParSigs(ctx context.Context, events []event) parsigsByMsg {
	type dedupKey struct {
		Pubkey   core.PubKey
		ShareIdx int
	}
	var (
		dedup = make(map[dedupKey]bool)
		datas = make(map[core.PubKey]map[[32]byte][]core.ParSignedData)
	)

	for _, e := range events {
		if e.parSig == nil {
			continue
		}
		key := dedupKey{Pubkey: e.pubkey, ShareIdx: e.parSig.ShareIdx}
		if dedup[key] {
			continue
		}
		dedup[key] = true

		root, err := e.parSig.MessageRoot()
		if err != nil {
			log.Warn(ctx, "Parsig message root", err)
			continue // Just log and ignore as this is highly unlikely and non-critical code.
		}

		inner, ok := datas[e.pubkey]
		if !ok {
			inner = make(map[[32]byte][]core.ParSignedData)
		}
		inner[root] = append(inner[root], *e.parSig)
		datas[e.pubkey] = inner
	}

	return datas
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
		// If we get a parSigDBExternal event, then the corresponding peer with e.shareIdx participated successfully.
		if e.step == parSigDBExternal || e.step == parSigDBInternal {
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
	if duty.Type == core.DutyExit || duty.Type == core.DutyBuilderRegistration {
		return true
	}

	// scheduled returns true if the provided duty type was scheduled for the above slot and pubkey.
	scheduled := func(typ core.DutyType) bool {
		for _, e := range allEvents[core.Duty{Slot: duty.Slot, Type: typ}] {
			if e.step == fetcher && e.pubkey == pubkey {
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
	if duty.Type == core.DutyPrepareSyncContribution || duty.Type == core.DutySyncMessage {
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

// FetcherFetched implements core.Tracker interface.
func (t *Tracker) FetcherFetched(ctx context.Context, duty core.Duty, set core.DutyDefinitionSet, stepErr error) {
	for pubkey := range set {
		select {
		case <-ctx.Done():
			return
		case <-t.quit:
			return
		case t.input <- event{
			duty:    duty,
			step:    fetcher,
			pubkey:  pubkey,
			stepErr: stepErr,
		}:
		}
	}
}

// ConsensusProposed implements core.Tracker interface.
func (t *Tracker) ConsensusProposed(ctx context.Context, duty core.Duty, set core.UnsignedDataSet, stepErr error) {
	for pubkey := range set {
		select {
		case <-ctx.Done():
			return
		case <-t.quit:
			return
		case t.input <- event{
			duty:    duty,
			step:    consensus,
			pubkey:  pubkey,
			stepErr: stepErr,
		}:
		}
	}
}

// DutyDBStored implements core.Tracker interface.
func (t *Tracker) DutyDBStored(ctx context.Context, duty core.Duty, set core.UnsignedDataSet, stepErr error) {
	for pubkey := range set {
		select {
		case <-ctx.Done():
			return
		case <-t.quit:
			return
		case t.input <- event{
			duty:    duty,
			step:    dutyDB,
			pubkey:  pubkey,
			stepErr: stepErr,
		}:
		}
	}
}

// ParSigDBStoredInternal implements core.Tracker interface.
func (t *Tracker) ParSigDBStoredInternal(ctx context.Context, duty core.Duty, set core.ParSignedDataSet, stepErr error) {
	for pubkey, parSig := range set {
		parSig := parSig
		select {
		case <-ctx.Done():
			return
		case <-t.quit:
			return
		case t.input <- event{
			duty:    duty,
			step:    parSigDBInternal,
			pubkey:  pubkey,
			parSig:  &parSig,
			stepErr: stepErr,
		}:
		}
	}
}

// ParSigDBStoredExternal implements core.Tracker interface.
func (t *Tracker) ParSigDBStoredExternal(ctx context.Context, duty core.Duty, set core.ParSignedDataSet, stepErr error) {
	for pubkey, parSig := range set {
		parSig := parSig
		select {
		case <-ctx.Done():
			return
		case <-t.quit:
			return
		case t.input <- event{
			duty:    duty,
			step:    parSigDBExternal,
			pubkey:  pubkey,
			parSig:  &parSig,
			stepErr: stepErr,
		}:
		}
	}
}

// SigAggAggregated implements core.Tracker interface.
func (t *Tracker) SigAggAggregated(ctx context.Context, duty core.Duty, pubkey core.PubKey, _ []core.ParSignedData, stepErr error) {
	select {
	case <-ctx.Done():
		return
	case <-t.quit:
		return
	case t.input <- event{
		duty:    duty,
		step:    sigAgg,
		pubkey:  pubkey,
		stepErr: stepErr,
	}:
	}
}

// BroadcasterBroadcast implements core.Tracker interface.
func (t *Tracker) BroadcasterBroadcast(ctx context.Context, duty core.Duty, pubkey core.PubKey, _ core.SignedData, stepErr error) {
	select {
	case <-ctx.Done():
		return
	case <-t.quit:
		return
	case t.input <- event{
		duty:    duty,
		step:    bcast,
		pubkey:  pubkey,
		stepErr: stepErr,
	}:
	}
}

func reportParSigs(ctx context.Context, duty core.Duty, parsigMsgs parsigsByMsg) {
	if parsigMsgs.MsgRootsConsistent() {
		return // Nothing to report.
	}

	inconsistentCounter.WithLabelValues(duty.Type.String()).Inc()

	for pubkey, parsigsByMsg := range parsigMsgs {
		if len(parsigMsgs) <= 1 {
			continue // Nothing to report for this pubkey.
		}

		// Group indexes by json for logging.
		indexesByJSON := make(map[string][]int)

		for _, parsigs := range parsigsByMsg {
			var key string
			for _, parsig := range parsigs {
				if key == "" {
					bytes, err := json.Marshal(parsig)
					if err != nil {
						continue // Ignore error, just skip it.
					}
					key = string(bytes)
				}
				indexesByJSON[key] = append(indexesByJSON[key], parsig.ShareIdx)
			}
		}

		if expectInconsistentParSigs(duty.Type) {
			log.Debug(ctx, "Inconsistent sync committee partial signed data",
				z.Any("pubkey", pubkey),
				z.Any("duty", duty),
				z.Any("data", indexesByJSON))
		} else {
			log.Warn(ctx, "Inconsistent partial signed data", nil,
				z.Any("pubkey", pubkey),
				z.Any("duty", duty),
				z.Any("data", indexesByJSON))
		}
	}
}

// expectInconsistentParSigs returns true if the duty type is expected to sometimes
// produce inconsistent partial signed data.
func expectInconsistentParSigs(duty core.DutyType) bool {
	return duty == core.DutySyncMessage || duty == core.DutySyncContribution
}
