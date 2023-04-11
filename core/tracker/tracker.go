// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tracker

import (
	"context"
	"encoding/json"
	"fmt"

	eth2http "github.com/attestantio/go-eth2-client/http"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/p2p"
)

// Steps arranged in the order they are triggered in the core workflow.
const (
	zero             step = iota
	fetcher               // Duty data fetched
	consensus             // Duty data consensus reached
	dutyDB                // Duty data stored in DutyDB
	validatorAPI          // Partial signed data from local VC submitted to vapi
	parSigDBInternal      // Partial signed data from local VC stored in parsigdb
	parSigEx              // Partial signed data from local VC to/from other peers in cluster
	parSigDBExternal      // Partial signed data from other VC stored in parsigdb
	sigAgg                // Partial signed data aggregated; emitted from sigagg
	aggSigDB              // Aggregated signed data stored in aggsigdb
	bcast                 // Aggregated data submitted to beacon node
	sentinel
)

var stepLabels = map[step]string{
	zero:             "unknown",
	fetcher:          "fetcher",
	consensus:        "consensus",
	dutyDB:           "duty_db",
	validatorAPI:     "validator_api",
	parSigDBInternal: "parsig_db_local",
	parSigEx:         "parsig_ex",
	parSigDBExternal: "parsig_db_external",
	sigAgg:           "sig_aggregation",
	aggSigDB:         "aggsig_db",
	bcast:            "bcast",
	sentinel:         "sentinel",
}

// step in the core workflow.
type step int

func (s step) String() string {
	return stepLabels[s]
}

// These constants are used for improving messages for why a duty failed.
const (
	// msgFetcherBN indicates a duty failed in the fetcher step when it failed
	// to fetch the required data from the beacon node API. This indicates a problem with
	// the upstream beacon node.
	msgFetcherBN = "couldn't fetch duty data from the beacon node"

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

	// msgFetcherError indicates duty failed in fetcher step with some unexpected error.
	// This indicates a problem in charon as it is unexpected.
	msgFetcherError = "couldn't fetch due to unexpected error"

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
	msgParSigDBInternal = "partial signature database didn't trigger partial signature exchange, this is unexpected"

	// msgParSigExReceive indicates that no partial signature for the duty was received from any peer.
	// This indicates all peers are offline or p2p network connection problems.
	msgParSigExReceive = "no partial signatures received from peers"

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

	// msgAggSigDB indicates a bug in the aggregated signature database as it is unexpected.
	msgAggSigDB = "bug: failed to store aggregated signature in aggsigdb"

	// msgBcast indicates that beacon node returned an error while submitting aggregated duty signature to beacon node.
	msgBcast = "failed to broadcast duty to beacon node"
)

// parsigsByMsg contains partial signatures grouped by message root grouped by pubkey.
type parsigsByMsg map[core.PubKey]map[[32]byte][]core.ParSignedData

// MsgRootsConsistent returns true if the all partial signatures have consistent message roots.
func (m parsigsByMsg) MsgRootsConsistent() bool {
	for _, roots := range m {
		if len(roots) > 1 {
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

	// parSig is an optional field only set by validatorAPI, parSigDBInternal and parSigExReceive events.
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
	failedDutyReporter func(ctx context.Context, duty core.Duty, failed bool, step step, reason string, err error)

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
	ctx = log.WithTopic(ctx, "tracker")
	defer close(t.quit)

	ignoreUnsupported := newUnsupportedIgnorer()

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

			parsigs := extractParSigs(ctx, t.events[duty])
			t.parSigReporter(ctx, duty, parsigs)

			// Analyse failed duties
			failed, failedStep, failedMsg, failedErr := analyseDutyFailed(duty, t.events, parsigs.MsgRootsConsistent())
			if ignoreUnsupported(ctx, duty, failed, failedStep, failedMsg) {
				continue // Ignore unsupported duties
			}

			t.failedDutyReporter(ctx, duty, failed, failedStep, failedMsg, failedErr)

			// Analyse peer participation
			participatedShares, unexpectedShares := analyseParticipation(duty, t.events)
			t.participationReporter(ctx, duty, failed, participatedShares, unexpectedShares)
		case duty := <-t.deleter.C():
			delete(t.events, duty)
		}
	}
}

// dutyFailedStep returns true if the duty failed. It also returns the step where the
// duty got stuck and the last error that component returned.
// If the duty didn't fail, it returns false and the zero step and a nil error.
// It assumes that all the input events are for a single duty.
// If the input events slice is empty, it returns true and the zero step.
func dutyFailedStep(es []event) (bool, step, error) {
	if len(es) == 0 {
		return true, zero, nil // Duty failed since no events.
	}

	// Group events by step.
	eventsByStep := make(map[step][]event)
	for _, e := range es {
		eventsByStep[e.step] = append(eventsByStep[e.step], e)
	}

	// Find last failed/successful step.
	var lastEvent event
	for step := sentinel - 1; step > zero; step-- {
		if len(eventsByStep[step]) == 0 {
			continue
		}

		lastEvent = eventsByStep[step][len(eventsByStep[step])-1]

		break
	}

	// Final step was successful.
	if lastEvent.step == bcast && lastEvent.stepErr == nil {
		return false, zero, nil
	}

	return true, lastEvent.step, lastEvent.stepErr
}

// analyseDutyFailed detects if the given duty failed.
//
// It returns true if the duty failed as well as the step
// where the duty got stuck and a human friendly error message explaining why
// as well as the error reported by the step/component.
//
// It returns false if the duty didn't fail, i.e., the duty
// didn't get stuck and completed the bcast step.
func analyseDutyFailed(duty core.Duty, allEvents map[core.Duty][]event, msgRootConsistent bool,
) (bool, step, string, error) {
	failed, failedStep, failedErr := dutyFailedStep(allEvents[duty])
	if !failed {
		return false, failedStep, "", nil
	}

	failedMsg := fmt.Sprintf("unexpected failure for %s duty at %s step", duty, failedStep)
	switch failedStep {
	case fetcher:
		return analyseFetcherFailed(duty, allEvents, failedErr)
	case consensus:
		if failedErr != nil {
			failedMsg = msgConsensus
		}
	case dutyDB:
		if failedErr != nil {
			failedMsg = msgDutyDB
		} else {
			failedStep = validatorAPI
			failedMsg = msgValidatorAPI
		}
	case parSigDBInternal:
		failedMsg = msgParSigDBInternal
	case parSigEx:
		if failedErr == nil {
			failedMsg = msgParSigExReceive
		}
	case parSigDBExternal:
		if failedErr != nil {
			return true, parSigDBExternal, msgParSigDBExternal, failedErr
		}

		if msgRootConsistent {
			failedMsg = msgParSigDBInsufficient
		} else {
			failedMsg = msgParSigDBInconsistent
			if expectInconsistentParSigs(duty.Type) {
				failedMsg = msgParSigDBInconsistentSync
			}
		}
	case sigAgg:
		if failedErr != nil {
			failedMsg = msgSigAgg
		}
	case aggSigDB:
		failedMsg = msgAggSigDB
	case bcast:
		failedMsg = msgBcast
	case zero:
		failedMsg = fmt.Sprintf("no events for %s duty", duty.String())
	default:
		failedMsg = fmt.Sprintf("%s duty failed at %s", duty.String(), failedStep.String()) // This should never happen.
	}

	return true, failedStep, failedMsg, failedErr
}

// analyseFetcherFailed returns whether the duty that got stuck in fetcher actually failed
// and the reason which might actually be due a pre-requisite duty that failed.
func analyseFetcherFailed(duty core.Duty, allEvents map[core.Duty][]event, fetchErr error) (bool, step, string, error) {
	failedMsg := msgFetcherError
	// Check for beacon api errors.
	var eth2Error eth2http.Error
	if errors.As(fetchErr, &eth2Error) {
		failedMsg = msgFetcherBN
	} else if !errors.Is(fetchErr, context.Canceled) && !errors.Is(fetchErr, context.DeadlineExceeded) {
		failedMsg = msgFetcherError
	}

	// Proposer duties depend on randao duty, so check if that was why it failed.
	if duty.Type == core.DutyProposer || duty.Type == core.DutyBuilderProposer {
		return analyseFetcherFailedProposer(duty, allEvents, fetchErr)
	}

	// Duty aggregator depend on prepare aggregator duty, so check if that was why it failed.
	if duty.Type == core.DutyAggregator {
		return analyseFetcherFailedAggregator(duty, allEvents, fetchErr)
	}

	// Duty sync contribution depends on prepare sync contribution duty, so check if that was why it failed.
	if duty.Type == core.DutySyncContribution {
		return analyseFetcherFailedSyncContribution(duty, allEvents, fetchErr)
	}

	return true, fetcher, failedMsg, fetchErr
}

// analyseFetcherFailed returns the reason behind why proposer duty failed which might actually
// be due to randao duty failed.
func analyseFetcherFailedProposer(duty core.Duty, allEvents map[core.Duty][]event, fetchErr error) (bool, step, string, error) {
	failedMsg := msgFetcherError

	// Proposer duties will fail if core.DutyRandao fails.
	// Ignoring error as it will be handled in DutyRandao analysis.
	randaoFailed, randaoStep, _ := dutyFailedStep(allEvents[core.NewRandaoDuty(duty.Slot)])
	if randaoFailed {
		switch randaoStep {
		case parSigEx:
			failedMsg = msgFetcherProposerNoExternalRandaos
		case parSigDBExternal:
			failedMsg = msgFetcherProposerFewRandaos
		case zero:
			failedMsg = msgFetcherProposerZeroRandaos
		default:
			failedMsg = msgFetcherProposerFailedRandao
		}
	}

	return true, fetcher, failedMsg, fetchErr
}

// analyseFetcherFailedAggregator returns the reason behind why aggregator duty failed which might actually
// be due to prepare aggregator duty or attester duty failed.
func analyseFetcherFailedAggregator(duty core.Duty, allEvents map[core.Duty][]event, fetchErr error) (bool, step, string, error) {
	failedMsg := msgFetcherError

	// No aggregators present for this slot.
	if fetchErr == nil {
		return false, fetcher, "", nil
	}

	// Aggregator duties will fail if core.DutyPrepareAggregator fails.
	// Ignoring error as it will be handled in DutyPrepareAggregator duty analysis.
	prepAggFailed, prepAggStep, _ := dutyFailedStep(allEvents[core.NewPrepareAggregatorDuty(duty.Slot)])
	if prepAggFailed {
		switch prepAggStep {
		case parSigEx:
			failedMsg = msgFetcherAggregatorNoExternalPrepares
		case parSigDBExternal:
			failedMsg = msgFetcherAggregatorFewPrepares
		case zero:
			failedMsg = msgFetcherAggregatorZeroPrepares
		default:
			failedMsg = msgFetcherAggregatorFailedPrepare
		}

		return true, fetcher, failedMsg, fetchErr
	}

	// Aggregator duties will fail if no attestation data in DutyDB.
	// Ignoring error as it will be handled in DutyAttester analysis.
	attFailed, attStep, _ := dutyFailedStep(allEvents[core.NewAttesterDuty(duty.Slot)])
	if attFailed && attStep <= dutyDB {
		failedMsg = msgFetcherAggregatorNoAttData
	}

	return true, fetcher, failedMsg, fetchErr
}

// analyseFetcherFailedSyncContribution returns the reason behind why sync contribution duty failed which might actually
// be due to prepare sync contribution duty or sync message duty failed.
func analyseFetcherFailedSyncContribution(duty core.Duty, allEvents map[core.Duty][]event, fetchErr error) (bool, step, string, error) {
	failedMsg := msgFetcherError

	// No sync committee aggregators present for this slot.
	if fetchErr == nil {
		return false, fetcher, "", nil
	}

	// Sync contribution duties will fail if core.DutyPrepareSyncContribution fails.
	// Ignoring error as it will be handled in DutyPrepareSyncContribution analysis.
	prepSyncConFailed, prepSyncConStep, _ := dutyFailedStep(allEvents[core.NewPrepareSyncContributionDuty(duty.Slot)])
	if prepSyncConFailed {
		switch prepSyncConStep {
		case parSigEx:
			failedMsg = msgFetcherSyncContributionNoExternalPrepares
		case parSigDBExternal:
			failedMsg = msgFetcherSyncContributionFewPrepares
		case zero:
			failedMsg = msgFetcherSyncContributionZeroPrepares
		default:
			failedMsg = msgFetcherSyncContributionFailedPrepare
		}

		return true, fetcher, failedMsg, fetchErr
	}

	// Sync contribution duties will fail if no sync message in AggSigDB.
	// Ignoring error as it will be handled in DutySyncMessage analysis.
	syncMsgFailed, syncMsgStep, _ := dutyFailedStep(allEvents[core.NewSyncMessageDuty(duty.Slot)])
	if syncMsgFailed && syncMsgStep <= aggSigDB {
		failedMsg = msgFetcherSyncContributionNoSyncMsg
	}

	return true, fetcher, failedMsg, fetchErr
}

// extractParSigs returns a mapping of unique partial signed data messages by peers (share index) by validator (pubkey).
func extractParSigs(ctx context.Context, events []event) parsigsByMsg {
	type dedupKey struct {
		Pubkey   core.PubKey
		ShareIdx int
	}
	var (
		dedup = make(map[dedupKey]bool)
		resp  = make(parsigsByMsg)
	)

	for _, e := range events {
		if e.parSig == nil {
			continue // Ignore events without parsigs.
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

		inner, ok := resp[e.pubkey]
		if !ok {
			inner = make(map[[32]byte][]core.ParSignedData)
		}
		inner[root] = append(inner[root], *e.parSig)
		resp[e.pubkey] = inner
	}

	return resp
}

// newFailedDutyReporter returns failed duty reporter which instruments failed duties.
func newFailedDutyReporter() func(ctx context.Context, duty core.Duty, failed bool, step step, reason string, err error) {
	// Initialise counters to 0 to avoid non-existent metrics issues when querying prometheus.
	for _, dutyType := range core.AllDutyTypes() {
		dutyFailed.WithLabelValues(dutyType.String()).Add(0)
		dutySuccess.WithLabelValues(dutyType.String()).Add(0)
		dutyExpect.WithLabelValues(dutyType.String()).Add(0)
	}

	return func(ctx context.Context, duty core.Duty, failed bool, step step, reason string, err error) {
		dutyExpect.WithLabelValues(duty.Type.String()).Inc()

		if !failed {
			dutySuccess.WithLabelValues(duty.Type.String()).Inc()
			return
		}

		dutyFailed.WithLabelValues(duty.Type.String()).Inc()

		log.Warn(ctx, "Duty failed", err,
			z.Any("step", step),
			z.Str("reason", reason),
		)
	}
}

// newUnsupportedIgnorer returns a filter that ignores duties that are not supported by the node.
func newUnsupportedIgnorer() func(ctx context.Context, duty core.Duty, failed bool, step step, reason string) bool {
	var (
		loggedNoAggregator    bool
		loggedNoContribution  bool
		aggregationSupported  bool
		contributionSupported bool
	)

	return func(ctx context.Context, duty core.Duty, failed bool, step step, reason string) bool {
		if !failed {
			if duty.Type == core.DutyAggregator {
				aggregationSupported = true
			}
			if duty.Type == core.DutySyncContribution {
				contributionSupported = true
			}

			return false
		}

		if !aggregationSupported && duty.Type == core.DutyAggregator && step == fetcher && reason == msgFetcherAggregatorZeroPrepares {
			if !loggedNoAggregator {
				log.Warn(ctx, "Ignoring attestation aggregation failures since VCs do not seem to support beacon committee selection aggregation", nil)
			}
			loggedNoAggregator = true

			return true
		}

		if !contributionSupported && duty.Type == core.DutySyncContribution && step == fetcher && reason == msgFetcherSyncContributionZeroPrepares {
			if !loggedNoContribution {
				log.Warn(ctx, "Ignoring sync contribution failures since VCs do not seem to support sync committee selection aggregation", nil)
			}
			loggedNoContribution = true

			return true
		}

		return false
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

	// Initialise counters to 0 to avoid non-existent metrics issues when querying prometheus.
	for _, dutyType := range core.AllDutyTypes() {
		duty := dutyType.String()
		for _, peer := range peers {
			participationSuccess.WithLabelValues(duty, peer.Name).Add(0)
			participationSuccessLegacy.WithLabelValues(duty, peer.Name).Add(0)
			participationMissed.WithLabelValues(duty, peer.Name).Add(0)
			participationExpect.WithLabelValues(duty, peer.Name).Add(0)
		}
	}

	return func(ctx context.Context, duty core.Duty, failed bool, participatedShares map[int]bool, unexpectedShares map[int]bool) {
		if len(participatedShares) == 0 && !failed {
			// Ignore participation metrics and log for noop duties (like DutyAggregator)
			return
		}

		var absentPeers []string
		for _, peer := range peers {
			if participatedShares[peer.ShareIdx()] {
				participationGauge.WithLabelValues(duty.Type.String(), peer.Name).Set(1)
				participationSuccess.WithLabelValues(duty.Type.String(), peer.Name).Inc()
				participationSuccessLegacy.WithLabelValues(duty.Type.String(), peer.Name).Inc()
				participationExpect.WithLabelValues(duty.Type.String(), peer.Name).Inc()
			} else if unexpectedShares[peer.ShareIdx()] {
				log.Warn(ctx, "Unexpected event found", nil, z.Str("peer", peer.Name), z.Str("duty", duty.String()))
				unexpectedEventsCounter.WithLabelValues(peer.Name).Inc()
			} else {
				absentPeers = append(absentPeers, peer.Name)
				participationGauge.WithLabelValues(duty.Type.String(), peer.Name).Set(0)
				participationMissed.WithLabelValues(duty.Type.String(), peer.Name).Inc()
				participationExpect.WithLabelValues(duty.Type.String(), peer.Name).Inc()
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
func (t *Tracker) FetcherFetched(duty core.Duty, set core.DutyDefinitionSet, stepErr error) {
	for pubkey := range set {
		select {
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
func (t *Tracker) ConsensusProposed(duty core.Duty, set core.UnsignedDataSet, stepErr error) {
	for pubkey := range set {
		select {
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
func (t *Tracker) DutyDBStored(duty core.Duty, set core.UnsignedDataSet, stepErr error) {
	for pubkey := range set {
		select {
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
func (t *Tracker) ParSigDBStoredInternal(duty core.Duty, set core.ParSignedDataSet, stepErr error) {
	for pubkey, parSig := range set {
		parSig := parSig
		select {
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

// ParSigExBroadcasted implements core.Tracker interface.
func (t *Tracker) ParSigExBroadcasted(duty core.Duty, set core.ParSignedDataSet, stepErr error) {
	for pubkey, parSig := range set {
		parSig := parSig
		select {
		case <-t.quit:
			return
		case t.input <- event{
			duty:    duty,
			step:    parSigEx,
			pubkey:  pubkey,
			parSig:  &parSig,
			stepErr: stepErr,
		}:
		}
	}
}

// ParSigDBStoredExternal implements core.Tracker interface.
func (t *Tracker) ParSigDBStoredExternal(duty core.Duty, set core.ParSignedDataSet, stepErr error) {
	for pubkey, parSig := range set {
		parSig := parSig
		select {
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
func (t *Tracker) SigAggAggregated(duty core.Duty, pubkey core.PubKey, _ []core.ParSignedData, stepErr error) {
	select {
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

// AggSigSBStored implements core.Tracker interface.
func (t *Tracker) AggSigDBStored(duty core.Duty, pubkey core.PubKey, _ core.SignedData, stepErr error) {
	select {
	case <-t.quit:
		return
	case t.input <- event{
		duty:    duty,
		step:    aggSigDB,
		pubkey:  pubkey,
		stepErr: stepErr,
	}:
	}
}

// BroadcasterBroadcast implements core.Tracker interface.
func (t *Tracker) BroadcasterBroadcast(duty core.Duty, pubkey core.PubKey, _ core.SignedData, stepErr error) {
	select {
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
