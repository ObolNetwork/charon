// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package scheduler

import (
	"context"
	"math"
	"sort"
	"sync"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/expbackoff"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

const trimEpochOffset = 3 // Trim cached duties after 3 epochs. Note inclusion delay calculation requires now-32 slot duties.

// delayFunc abstracts slot offset delaying/sleeping for deterministic tests.
type delayFunc func(duty core.Duty, deadline time.Time) <-chan time.Time

// schedSlotFunc is a function type that is called before every scheduled slot.
// Used only in testing.
type schedSlotFunc func(ctx context.Context, slot core.Slot)

// NewForT returns a new scheduler for testing using a fake clock.
func NewForT(t *testing.T, clock clockwork.Clock, delayFunc delayFunc, builderRegistrations []*eth2api.VersionedSignedValidatorRegistration,
	eth2Cl eth2wrap.Client, schedSlotFunc schedSlotFunc, builderEnabled bool,
) *Scheduler {
	t.Helper()

	s, err := New(builderRegistrations, eth2Cl, builderEnabled)
	require.NoError(t, err)

	s.clock = clock
	s.delayFunc = delayFunc
	s.schedSlotFunc = schedSlotFunc

	return s
}

// New returns a new scheduler.
func New(builderRegistrations []*eth2api.VersionedSignedValidatorRegistration, eth2Cl eth2wrap.Client, builderEnabled bool) (*Scheduler, error) {
	return &Scheduler{
		eth2Cl:                     eth2Cl,
		builderRegistrations:       builderRegistrations,
		submittedRegistrationEpoch: math.MaxUint64,
		quit:                       make(chan struct{}),
		duties:                     make(map[core.Duty]core.DutyDefinitionSet),
		dutiesByEpoch:              make(map[uint64][]core.Duty),
		epochResolved:              make(map[uint64]chan struct{}),
		clock:                      clockwork.NewRealClock(),
		delayFunc: func(_ core.Duty, deadline time.Time) <-chan time.Time {
			return time.After(time.Until(deadline))
		},
		metricSubmitter: newMetricSubmitter(),
		resolvedEpoch:   math.MaxInt64,
		resolvingEpoch:  math.MaxInt64,
		builderEnabled:  builderEnabled,
	}, nil
}

type Scheduler struct {
	eth2Cl                     eth2wrap.Client
	builderRegistrations       []*eth2api.VersionedSignedValidatorRegistration
	submittedRegistrationEpoch uint64
	registrationMutex          sync.Mutex
	quit                       chan struct{}
	clock                      clockwork.Clock
	delayFunc                  delayFunc
	metricSubmitter            metricSubmitter
	resolvedEpoch              uint64
	resolvingEpoch             uint64
	duties                     map[core.Duty]core.DutyDefinitionSet
	dutiesByEpoch              map[uint64][]core.Duty
	dutiesMutex                sync.RWMutex
	dutySubs                   []func(context.Context, core.Duty, core.DutyDefinitionSet) error
	slotSubs                   []func(context.Context, core.Slot) error
	fetcherFetchOnly           func(context.Context, core.Duty, core.DutyDefinitionSet, string) error
	builderEnabled             bool
	schedSlotFunc              schedSlotFunc
	epochResolved              map[uint64]chan struct{} // Notification channels for epoch resolution
	eventTriggeredAttestations sync.Map                 // Track attestation duties triggered via sse block event (map[uint64]bool)
}

// SubscribeDuties subscribes a callback function for triggered duties.
// Note this should be called *before* Start.
func (s *Scheduler) SubscribeDuties(fn func(context.Context, core.Duty, core.DutyDefinitionSet) error) {
	s.dutySubs = append(s.dutySubs, fn)
}

// RegisterFetcherFetchOnly registers the fetcher's FetchOnly method for early attestation fetching.
// Note this should be called *before* Start.
func (s *Scheduler) RegisterFetcherFetchOnly(fn func(context.Context, core.Duty, core.DutyDefinitionSet, string) error) {
	s.fetcherFetchOnly = fn
}

// SubscribeSlots subscribes a callback function for triggered slots.
// Note this should be called *before* Start.
// TODO(corver): Add subscriber names for improved logging.
func (s *Scheduler) SubscribeSlots(fn func(context.Context, core.Slot) error) {
	s.slotSubs = append(s.slotSubs, fn)
}

func (s *Scheduler) Stop() {
	close(s.quit)
}

// getSubmittedRegistrationEpoch returns the last epoch for which registrations were submitted.
func (s *Scheduler) getSubmittedRegistrationEpoch() uint64 {
	s.registrationMutex.Lock()
	defer s.registrationMutex.Unlock()
	return s.submittedRegistrationEpoch
}

// setSubmittedRegistrationEpoch sets the last epoch for which registrations were submitted.
func (s *Scheduler) setSubmittedRegistrationEpoch(epoch uint64) {
	s.registrationMutex.Lock()
	defer s.registrationMutex.Unlock()
	s.submittedRegistrationEpoch = epoch
}

// Run blocks and runs the scheduler until Stop is called.
func (s *Scheduler) Run() error {
	ctx := log.WithTopic(context.Background(), "sched")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	waitChainStart(ctx, s.eth2Cl, s.clock)
	waitBeaconSync(ctx, s.eth2Cl, s.clock)

	// Submit validator registrations on startup if builder is enabled.
	// This ensures registrations are sent before the first proposal opportunity.
	if s.builderEnabled {
		go s.submitValidatorRegistrations(ctx, 0)
	}

	slotTicker, err := newSlotTicker(ctx, s.eth2Cl, s.clock)
	if err != nil {
		return err
	}

	for {
		select {
		case <-s.quit:
			return nil
		case slot := <-slotTicker:
			log.Debug(ctx, "Slot ticked", z.U64("slot", slot.Slot)) // Not adding slot to context since duty will be added that also contains slot.

			instrumentSlot(slot)

			// emitCoreSlot doesn't need to be called inside a goroutine
			// as it calls subscribers in their separate goroutines.
			s.emitCoreSlot(ctx, slot)

			s.scheduleSlot(ctx, slot)
		}
	}
}

// HandleChainReorgEvent is connected to SSE Listener and handles chain reorg events.
func (s *Scheduler) HandleChainReorgEvent(ctx context.Context, epoch eth2p0.Epoch) {
	if featureset.Enabled(featureset.SSEReorgDuties) {
		resolvedEpoch := s.getResolvedEpoch()
		if uint64(epoch) < resolvedEpoch {
			// Removing current epoch duties, because of a chain reorg.
			s.trimDuties(resolvedEpoch)
			// Duties are to be resolved again in the next slot by scheduleSlot().
			s.setResolvedEpoch(math.MaxInt64)

			log.Info(ctx, "Chain reorg event handled, duties trimmed", z.U64("reorg_epoch", uint64(epoch)), z.U64("resolved_epoch", resolvedEpoch))
		}
	} else {
		log.Warn(ctx, "Chain reorg event ignored due to disabled SSEReorgDuties feature", nil, z.U64("reorg_epoch", uint64(epoch)))
	}
}

// HandleBlockEvent handles SSE "block" events (block imported to fork choice) and triggers early attestation data fetching.
func (s *Scheduler) HandleBlockEvent(ctx context.Context, slot eth2p0.Slot, bnAddr string) {
	if s.fetcherFetchOnly == nil {
		log.Warn(ctx, "Early attestation data fetch skipped, fetcher fetch-only function not registered", nil, z.U64("slot", uint64(slot)), z.Str("bn_addr", bnAddr))
		return
	}

	// Only process if either feature flag is enabled
	if !featureset.Enabled(featureset.FetchAttOnBlock) && !featureset.Enabled(featureset.FetchAttOnBlockWithDelay) {
		return
	}

	duty := core.Duty{
		Slot: uint64(slot),
		Type: core.DutyAttester,
	}

	defSet, ok := s.getDutyDefinitionSet(duty)
	if !ok {
		// Nothing for this duty
		return
	}

	_, alreadyTriggered := s.eventTriggeredAttestations.LoadOrStore(uint64(slot), true)
	if alreadyTriggered {
		return
	}

	// Clone defSet to prevent race conditions when it's modified or trimmed
	clonedDefSet, err := defSet.Clone()
	if err != nil {
		log.Error(ctx, "Failed to clone duty definition set for early fetch", err)
		return
	}

	log.Debug(ctx, "Early attestation data fetch triggered by SSE block event", z.U64("slot", uint64(slot)), z.Str("bn_addr", bnAddr))

	// Fetch attestation data early without triggering consensus
	// Use background context to prevent cancellation if SSE connection drops
	go func() {
		fetchCtx := log.CopyFields(context.Background(), ctx)
		if err := s.fetcherFetchOnly(fetchCtx, duty, clonedDefSet, bnAddr); err != nil {
			log.Warn(fetchCtx, "Early attestation data fetch failed", err, z.U64("slot", uint64(slot)), z.Str("bn_addr", bnAddr))
		}
	}()
}

// emitCoreSlot calls all slot subscriptions asynchronously with the provided slot.
func (s *Scheduler) emitCoreSlot(ctx context.Context, slot core.Slot) {
	for _, sub := range s.slotSubs {
		go func(sub func(context.Context, core.Slot) error) {
			err := sub(ctx, slot)
			if err != nil {
				log.Error(ctx, "Failed to emit scheduled slot event", err, z.U64("slot", slot.Slot))
			}
		}(sub)
	}
}

// GetDutyDefinition returns the definition for a duty or core.ErrNotFound if no definitions exist for a resolved epoch
// or another error.
func (s *Scheduler) GetDutyDefinition(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
	if duty.Type == core.DutyBuilderProposer {
		return nil, core.ErrDeprecatedDutyBuilderProposer
	}

	_, slotsPerEpoch, err := eth2wrap.FetchSlotsConfig(ctx, s.eth2Cl)
	if err != nil {
		return nil, err
	}

	epoch := duty.Slot / slotsPerEpoch

	// This has to be very rare event, when the requested epoch is being resolved.
	// We wait for the epoch to be resolved before returning the duty definition.
	if s.isResolvingEpoch(epoch) {
		ch := s.getEpochResolvedChan(epoch)
		select {
		case <-ctx.Done():
			return nil, errors.Wrap(ctx.Err(), "context cancelled while waiting for epoch to resolve")
		case <-ch:
			// Epoch resolved, continue
		}
	}

	if !s.isEpochResolved(epoch) {
		return nil, errors.New("epoch not resolved yet",
			z.Str("duty", duty.String()), z.U64("epoch", epoch))
	}

	if s.isEpochTrimmed(epoch) {
		return nil, errors.New("epoch already trimmed",
			z.Str("duty", duty.String()), z.U64("epoch", epoch))
	}

	defSet, ok := s.getDutyDefinitionSet(duty)
	if !ok {
		return nil, errors.Wrap(core.ErrNotFound, "duty not present for resolved epoch",
			z.Any("duty", duty), z.U64("epoch", epoch))
	}

	return defSet.Clone() // Clone before returning.
}

// scheduleSlot resolves upcoming duties and triggers resolved duties for the slot.
func (s *Scheduler) scheduleSlot(ctx context.Context, slot core.Slot) {
	if s.schedSlotFunc != nil {
		s.schedSlotFunc(ctx, slot)
	}

	if s.getResolvedEpoch() != slot.Epoch() {
		log.Debug(ctx, "Resolving duties for slot", z.U64("slot", slot.Slot), z.U64("epoch", slot.Epoch()))

		if err := s.resolveDuties(ctx, slot); err != nil {
			log.Warn(ctx, "Resolving duties error (retrying next slot)", err, z.U64("slot", slot.Slot))
		}
	}

	// Submit validator registrations asynchronously to avoid blocking duty triggering.
	// Only submit at slot 0 of each epoch, delayed to end of slot to reduce BN load.
	if s.builderEnabled && s.getSubmittedRegistrationEpoch() != slot.Epoch() {
		if slot.Slot%slot.SlotsPerEpoch == 0 {
			go s.submitValidatorRegistrationsDelayed(ctx, slot)
		}
	}

	for _, dutyType := range core.AllDutyTypes() {
		duty := core.Duty{
			Slot: slot.Slot,
			Type: dutyType,
		}

		var span trace.Span

		dutyCtx := log.WithCtx(ctx, z.Any("duty", duty))

		dutyCtx, span = core.StartDutyTrace(dutyCtx, duty, "core/scheduler.scheduleSlot")

		defSet, ok := s.getDutyDefinitionSet(duty)
		if !ok {
			span.End()
			// Nothing for this duty.
			continue
		}

		// Trigger duty async
		go func(duty core.Duty, defSet core.DutyDefinitionSet) {
			defer span.End()

			// Special handling for attester duties when FetchAttOnBlock features are enabled
			if duty.Type == core.DutyAttester && (featureset.Enabled(featureset.FetchAttOnBlock) || featureset.Enabled(featureset.FetchAttOnBlockWithDelay)) {
				if !s.waitForBlockEventOrTimeout(dutyCtx, slot) {
					return // context cancelled
				}

				s.eventTriggeredAttestations.Store(slot.Slot, true)
			} else if !delaySlotOffset(dutyCtx, slot, duty, s.delayFunc) {
				return // context cancelled
			}

			instrumentDuty(duty, defSet)

			for _, sub := range s.dutySubs {
				clone, err := defSet.Clone() // Clone for each subscriber.
				if err != nil {
					log.Error(dutyCtx, "Failed to clone duty definition set", err)
					return
				}

				if err := sub(dutyCtx, duty, clone); err != nil {
					log.Error(dutyCtx, "Failed to trigger duty subscriber", err, z.U64("slot", slot.Slot))
				}
			}
		}(duty, defSet)

		if slot.LastInEpoch() {
			err := s.resolveDuties(ctx, slot.Next())
			if err != nil {
				log.Warn(ctx, "Resolving duties error (retrying next slot)", err, z.U64("slot", slot.Slot))
			}
		}
	}
}

// delaySlotOffset blocks until the slot offset for the duty has been reached and return true.
// It returns false if the context is cancelled.
func delaySlotOffset(ctx context.Context, slot core.Slot, duty core.Duty, delayFunc delayFunc) bool {
	fn, ok := slotOffsets[duty.Type]
	if !ok {
		return true
	}

	// Calculate delay until slot offset
	offset := fn(slot.SlotDuration)
	deadline := slot.Time.Add(offset)

	select {
	case <-ctx.Done():
		return false
	case <-delayFunc(duty, deadline):
		return true
	}
}

// waitForBlockEventOrTimeout waits until the fallback timeout is reached.
// If FetchAttOnBlockWithDelay is enabled, timeout is T=1/3+300ms, otherwise T=1/3.
// Returns false if the context is cancelled, true otherwise.
func (s *Scheduler) waitForBlockEventOrTimeout(ctx context.Context, slot core.Slot) bool {
	// Calculate fallback timeout
	fn, ok := slotOffsets[core.DutyAttester]
	if !ok {
		log.Warn(ctx, "Slot offset not found for attester duty, proceeding immediately", nil, z.U64("slot", slot.Slot))
		return true
	}

	offset := fn(slot.SlotDuration)
	// Add 300ms delay only if FetchAttOnBlockWithDelay is enabled
	if featureset.Enabled(featureset.FetchAttOnBlockWithDelay) {
		offset += 300 * time.Millisecond
	}

	fallbackDeadline := slot.Time.Add(offset)

	select {
	case <-ctx.Done():
		return false
	case <-s.clock.After(time.Until(fallbackDeadline)):
		// Check if block event triggered early fetch
		if _, triggered := s.eventTriggeredAttestations.Load(slot.Slot); !triggered {
			if featureset.Enabled(featureset.FetchAttOnBlockWithDelay) {
				log.Debug(ctx, "Proceeding with attestation at T=1/3+300ms (no early block event)",
					z.U64("slot", slot.Slot))
			} else {
				log.Debug(ctx, "Proceeding with attestation at T=1/3 (no early block event)",
					z.U64("slot", slot.Slot))
			}
		}

		return true
	}
}

// resolveDuties resolves the duties for the slot's epoch, caching the results.
func (s *Scheduler) resolveDuties(ctx context.Context, slot core.Slot) error {
	s.setResolvingEpoch(slot.Epoch())
	defer s.setResolvingEpoch(math.MaxInt64)

	vals, err := resolveActiveValidators(ctx, s.eth2Cl, s.metricSubmitter, slot.Epoch())
	if err != nil {
		return err
	}

	activeValsGauge.Set(float64(len(vals)))

	if len(vals) == 0 {
		log.Info(ctx, "No active validators for slot", z.U64("slot", slot.Slot))
		s.setResolvedEpoch(slot.Epoch())

		return nil
	}

	err = s.resolveAttDuties(ctx, slot, vals)
	if err != nil {
		return err
	}

	err = s.resolveProDuties(ctx, slot, vals)
	if err != nil {
		return err
	}

	err = s.resolveSyncCommDuties(ctx, slot, vals)
	if err != nil {
		return err
	}

	s.setResolvedEpoch(slot.Epoch())
	s.trimDuties(slot.Epoch() - trimEpochOffset)

	return nil
}

// resolveAttDuties resolves attester duties for the given validators.
func (s *Scheduler) resolveAttDuties(ctx context.Context, slot core.Slot, vals validators) error {
	var attDuties []*eth2v1.AttesterDuty

	if featureset.Enabled(featureset.DisableDutiesCache) {
		eth2Resp, err := s.eth2Cl.AttesterDuties(ctx, &eth2api.AttesterDutiesOpts{Epoch: eth2p0.Epoch(slot.Epoch()), Indices: vals.Indexes()})
		if err != nil {
			return err
		}

		attDuties = eth2Resp.Data
	} else {
		cachedResp, err := s.eth2Cl.AttesterDutiesCache(ctx, eth2p0.Epoch(slot.Epoch()), vals.Indexes())
		if err != nil {
			return err
		}

		attDuties = cachedResp
	}

	// Check if any of the attester duties returned are nil.
	for _, duty := range attDuties {
		if duty == nil {
			return errors.New("attester duty is nil")
		}
	}

	remaining := make(map[eth2p0.ValidatorIndex]bool)
	for _, index := range vals.Indexes() {
		remaining[index] = true
	}

	// Sort so logging below in ascending slot order.
	sort.Slice(attDuties, func(i, j int) bool {
		return attDuties[i].Slot < attDuties[j].Slot
	})

	for _, attDuty := range attDuties {
		delete(remaining, attDuty.ValidatorIndex)

		if attDuty.Slot < eth2p0.Slot(slot.Slot) {
			// Skip duties for earlier slots in initial epoch.
			continue
		}

		duty := core.NewAttesterDuty(uint64(attDuty.Slot))

		pubkey, ok := vals.PubKeyFromIndex(attDuty.ValidatorIndex)
		if !ok {
			log.Warn(ctx, "Received attester duty for unknown validator. The validator may not be part of this cluster. Ignoring. If edit command was recently executed, Charon and/or VC might have not been restarted or not read the new keys properly", nil, z.U64("vidx", uint64(attDuty.ValidatorIndex)), z.U64("slot", slot.Slot))
			continue
		}

		if core.PubKeyFrom48Bytes(attDuty.PubKey) != pubkey {
			return errors.New("invalid attester duty pubkey")
		}

		if !s.setDutyDefinition(duty, slot.Epoch(), pubkey, core.NewAttesterDefinition(attDuty)) {
			continue
		}

		log.Info(ctx, "Resolved attester duty",
			z.U64("slot", uint64(attDuty.Slot)),
			z.U64("vidx", uint64(attDuty.ValidatorIndex)),
			z.Any("pubkey", pubkey),
			z.U64("epoch", slot.Epoch()),
		)

		// Schedule aggregation duty as well.
		aggDuty := core.NewAggregatorDuty(uint64(attDuty.Slot))

		if !s.setDutyDefinition(aggDuty, slot.Epoch(), pubkey, core.NewAttesterDefinition(attDuty)) {
			continue
		}
	}

	if len(remaining) > 0 {
		log.Warn(ctx, "Missing attester duties from beacon node. Some validators did not receive duty assignments. Check beacon node sync status and validator activation", nil,
			z.U64("slot", slot.Slot),
			z.U64("epoch", slot.Epoch()),
			z.Any("validator_indexes", remaining),
		)
	}

	return nil
}

// resolveProDuties resolves proposer duties for the given validators.
func (s *Scheduler) resolveProDuties(ctx context.Context, slot core.Slot, vals validators) error {
	var proDuties []*eth2v1.ProposerDuty

	if featureset.Enabled(featureset.DisableDutiesCache) {
		eth2Resp, err := s.eth2Cl.ProposerDuties(ctx, &eth2api.ProposerDutiesOpts{Epoch: eth2p0.Epoch(slot.Epoch()), Indices: vals.Indexes()})
		if err != nil {
			return err
		}

		proDuties = eth2Resp.Data
	} else {
		cachedResp, err := s.eth2Cl.ProposerDutiesCache(ctx, eth2p0.Epoch(slot.Epoch()), vals.Indexes())
		if err != nil {
			return err
		}

		proDuties = cachedResp
	}

	// Check if any of the proposer duties returned are nil.
	for _, duty := range proDuties {
		if duty == nil {
			return errors.New("proposer duty is nil")
		}
	}

	for _, proDuty := range proDuties {
		if proDuty.Slot < eth2p0.Slot(slot.Slot) {
			// Skip duties for earlier slots in initial epoch.
			continue
		}

		duty := core.NewProposerDuty(uint64(proDuty.Slot))

		pubkey, ok := vals.PubKeyFromIndex(proDuty.ValidatorIndex)
		if !ok {
			log.Warn(ctx, "Received proposer duty for unknown validator. The validator may not be part of this cluster. Ignoring", nil, z.U64("vidx", uint64(proDuty.ValidatorIndex)), z.U64("slot", slot.Slot))
			continue
		}

		if core.PubKeyFrom48Bytes(proDuty.PubKey) != pubkey {
			return errors.New("invalid proposer duty pubkey")
		}

		if !s.setDutyDefinition(duty, slot.Epoch(), pubkey, core.NewProposerDefinition(proDuty)) {
			continue
		}

		log.Info(ctx, "Resolved proposer duty",
			z.U64("slot", uint64(proDuty.Slot)),
			z.U64("vidx", uint64(proDuty.ValidatorIndex)),
			z.Any("pubkey", pubkey),
			z.U64("epoch", slot.Epoch()),
		)
	}

	return nil
}

// resolveSyncCommDuties resolves sync committee duties for the validators in the given slot's epoch, caching the results.
func (s *Scheduler) resolveSyncCommDuties(ctx context.Context, slot core.Slot, vals validators) error {
	var duties []*eth2v1.SyncCommitteeDuty

	if featureset.Enabled(featureset.DisableDutiesCache) {
		eth2Resp, err := s.eth2Cl.SyncCommitteeDuties(ctx, &eth2api.SyncCommitteeDutiesOpts{Epoch: eth2p0.Epoch(slot.Epoch()), Indices: vals.Indexes()})
		if err != nil {
			return err
		}

		duties = eth2Resp.Data
	} else {
		cachedResp, err := s.eth2Cl.SyncCommDutiesCache(ctx, eth2p0.Epoch(slot.Epoch()), vals.Indexes())
		if err != nil {
			return err
		}

		duties = cachedResp
	}

	// Check if any of the sync committee duties returned are nil.
	for _, duty := range duties {
		if duty == nil {
			return errors.New("sync committee duty is nil")
		}
	}

	for _, syncCommDuty := range duties {
		vIdx := syncCommDuty.ValidatorIndex

		pubkey, ok := vals.PubKeyFromIndex(vIdx)
		if !ok {
			log.Warn(ctx, "Received sync committee duty for unknown validator. The validator may not be part of this cluster. Ignoring", nil, z.U64("vidx", uint64(vIdx)), z.U64("slot", slot.Slot))
			continue
		}

		if core.PubKeyFrom48Bytes(syncCommDuty.PubKey) != pubkey {
			return errors.New("invalid sync committee duty pubkey")
		}

		// TODO(xenowits): sync committee duties start in the slot before the sync committee period.
		// Refer: https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#sync-committee
		var (
			startSlot = slot
			currEpoch = slot.Epoch()
		)

		for sl := startSlot; sl.Epoch() == currEpoch; sl = sl.Next() {
			// Schedule sync committee contribution aggregation.
			duty := core.NewSyncContributionDuty(sl.Slot)

			s.setDutyDefinition(duty, slot.Epoch(), pubkey, core.NewSyncCommitteeDefinition(syncCommDuty))
		}

		log.Info(ctx, "Resolved sync committee duty",
			z.U64("vidx", uint64(vIdx)),
			z.Any("pubkey", pubkey),
			z.U64("epoch", slot.Epoch()),
		)
	}

	return nil
}

func (s *Scheduler) getDutyDefinitionSet(duty core.Duty) (core.DutyDefinitionSet, bool) {
	s.dutiesMutex.RLock()
	defer s.dutiesMutex.RUnlock()

	defSet, ok := s.duties[duty]

	return defSet, ok
}

// setDutyDefinition returns true if the duty definition for the pubkey was set, false if it was already set.
func (s *Scheduler) setDutyDefinition(duty core.Duty, epoch uint64, pubkey core.PubKey, set core.DutyDefinition) bool {
	s.dutiesMutex.Lock()
	defer s.dutiesMutex.Unlock()

	defSet, ok := s.duties[duty]
	if !ok {
		defSet = make(core.DutyDefinitionSet)
	}

	if _, ok := defSet[pubkey]; ok {
		return false
	}

	defSet[pubkey] = set
	s.duties[duty] = defSet
	s.dutiesByEpoch[epoch] = append(s.dutiesByEpoch[epoch], duty)

	return true
}

func (s *Scheduler) getResolvedEpoch() uint64 {
	s.dutiesMutex.RLock()
	defer s.dutiesMutex.RUnlock()

	return s.resolvedEpoch
}

func (s *Scheduler) setResolvedEpoch(epoch uint64) {
	s.dutiesMutex.Lock()
	defer s.dutiesMutex.Unlock()

	s.resolvedEpoch = epoch

	// Notify waiters that epoch is resolved
	if ch, ok := s.epochResolved[epoch]; ok {
		close(ch)
		delete(s.epochResolved, epoch)
	}
}

// getEpochResolvedChan returns a channel that will be closed when the epoch is resolved.
func (s *Scheduler) getEpochResolvedChan(epoch uint64) <-chan struct{} {
	s.dutiesMutex.Lock()
	defer s.dutiesMutex.Unlock()

	// If already resolved, return closed channel
	if s.resolvedEpoch != math.MaxInt64 && s.resolvedEpoch >= epoch {
		ch := make(chan struct{})
		close(ch)

		return ch
	}

	// Create or reuse notification channel
	ch, ok := s.epochResolved[epoch]
	if !ok {
		ch = make(chan struct{})
		s.epochResolved[epoch] = ch
	}

	return ch
}

func (s *Scheduler) setResolvingEpoch(epoch uint64) {
	s.dutiesMutex.Lock()
	defer s.dutiesMutex.Unlock()

	s.resolvingEpoch = epoch
}

func (s *Scheduler) isResolvingEpoch(epoch uint64) bool {
	s.dutiesMutex.RLock()
	defer s.dutiesMutex.RUnlock()

	if s.resolvingEpoch == math.MaxInt64 {
		return false
	}

	return s.resolvingEpoch == epoch
}

// isEpochResolved returns true if the epoch is resolved.
func (s *Scheduler) isEpochResolved(epoch uint64) bool {
	if s.getResolvedEpoch() == math.MaxInt64 {
		return false
	}

	return s.getResolvedEpoch() >= epoch
}

// isEpochTrimmed returns true if the epoch's duties have been trimmed.
func (s *Scheduler) isEpochTrimmed(epoch uint64) bool {
	if s.getResolvedEpoch() == math.MaxInt64 {
		return false
	}

	return s.getResolvedEpoch() >= epoch+trimEpochOffset
}

// trimDuties deletes all duties for the provided epoch.
func (s *Scheduler) trimDuties(epoch uint64) {
	s.dutiesMutex.Lock()
	defer s.dutiesMutex.Unlock()

	duties := s.dutiesByEpoch[epoch]
	if len(duties) == 0 {
		return
	}

	for _, duty := range duties {
		delete(s.duties, duty)
	}

	delete(s.dutiesByEpoch, epoch)

	if featureset.Enabled(featureset.FetchAttOnBlock) || featureset.Enabled(featureset.FetchAttOnBlockWithDelay) {
		s.trimEventTriggeredAttestations(epoch)
	}
}

// trimEventTriggeredAttestations removes old slot entries from eventTriggeredAttestations.
func (s *Scheduler) trimEventTriggeredAttestations(epoch uint64) {
	ctx := context.Background()

	_, slotsPerEpoch, err := eth2wrap.FetchSlotsConfig(ctx, s.eth2Cl)
	if err != nil {
		log.Warn(ctx, "Failed to fetch slots config for trimming event triggered attestations", err, z.U64("epoch", epoch))
		return
	}

	minSlotToKeep := (epoch + 1) * slotsPerEpoch // first slot of next epoch

	s.eventTriggeredAttestations.Range(func(key, _ any) bool {
		slot, ok := key.(uint64)
		if !ok {
			return true // continue iteration
		}

		if slot < minSlotToKeep {
			s.eventTriggeredAttestations.Delete(slot)
		}

		return true // continue iteration
	})
}

// submitValidatorRegistrationsDelayed delays submission until near the end of slot 0 to reduce BN load.
func (s *Scheduler) submitValidatorRegistrationsDelayed(ctx context.Context, slot core.Slot) {
	slotDuration, _, err := eth2wrap.FetchSlotsConfig(ctx, s.eth2Cl)
	if err != nil {
		log.Warn(ctx, "Failed to fetch slot duration for delayed registration", err)
		// Fall back to immediate submission
		s.submitValidatorRegistrations(ctx, slot.Epoch())
		return
	}

	// Wait for 75% of slot duration before submitting (end of slot 0)
	delay := (slotDuration * 3) / 4

	select {
	case <-s.quit:
		return
	case <-s.clock.After(delay):
		s.submitValidatorRegistrations(ctx, slot.Epoch())
	}
}

// submitValidatorRegistrations submits the validator registrations for all DVs.
func (s *Scheduler) submitValidatorRegistrations(ctx context.Context, epoch uint64) {
	if s.getSubmittedRegistrationEpoch() == epoch {
		return
	}

	submitRegistrationCounter.Add(1)

	err := s.eth2Cl.SubmitValidatorRegistrations(ctx, s.builderRegistrations)
	if err != nil {
		submitRegistrationErrors.Add(1)
		log.Error(ctx, "Failed to submit validator registrations", err, z.U64("epoch", epoch))
	} else {
		log.Info(ctx, "Submitted validator registrations", z.Int("count", len(s.builderRegistrations)), z.U64("epoch", epoch))
		s.setSubmittedRegistrationEpoch(epoch)
	}
}

// newSlotTicker returns a blocking channel that will be populated with new slots in real time.
// It is also populated with the current slot immediately.
func newSlotTicker(ctx context.Context, eth2Cl eth2wrap.Client, clock clockwork.Clock) (<-chan core.Slot, error) {
	genesisTime, err := eth2wrap.FetchGenesisTime(ctx, eth2Cl)
	if err != nil {
		return nil, err
	}

	slotDuration, slotsPerEpoch, err := eth2wrap.FetchSlotsConfig(ctx, eth2Cl)
	if err != nil {
		return nil, err
	}

	if slotDuration == 0 {
		return nil, errors.New("slot duration is zero")
	}

	currentSlot := func() core.Slot {
		chainAge := clock.Since(genesisTime)
		slot := int64(chainAge / slotDuration)
		startTime := genesisTime.Add(time.Duration(slot) * slotDuration)

		return core.Slot{
			Slot:          uint64(slot),
			Time:          startTime,
			SlotsPerEpoch: slotsPerEpoch,
			SlotDuration:  slotDuration,
		}
	}

	resp := make(chan core.Slot)

	go func() {
		slot := currentSlot()

		for {
			select {
			case <-ctx.Done():
				return
			case <-clock.After(slot.Time.Sub(clock.Now())):
			}

			// Avoid "thundering herd" problem by skipping slots if missed due
			// to pause-the-world events (i.e. resources are already constrained).
			if clock.Now().After(slot.Next().Time) {
				actual := currentSlot()
				log.Warn(ctx, "Slot(s) skipped", nil, z.U64("actual_slot", actual.Slot), z.U64("expect_slot", slot.Slot))
				skipCounter.Inc()

				slot = actual
			}

			select {
			case <-ctx.Done():
				return
			case resp <- slot:
			}

			slot = slot.Next()
		}
	}()

	return resp, nil
}

// resolveActiveValidators returns the active validators (including their validator index) for the slot.
func resolveActiveValidators(ctx context.Context, eth2Cl eth2wrap.Client, submitter metricSubmitter, epoch uint64,
) (validators, error) {
	eth2Resp, err := eth2Cl.CompleteValidators(ctx)
	if err != nil {
		return nil, err
	}

	var resp []validator

	for index, val := range eth2Resp {
		if val == nil || val.Validator == nil {
			return nil, errors.New("validator data is nil")
		}

		pubkey, err := core.PubKeyFromBytes(val.Validator.PublicKey[:])
		if err != nil {
			return nil, err
		}

		submitter(pubkey, val.Balance, val.Status.String())

		// Check for active validators for the given epoch.
		// The activation epoch needs to be checked in cases where this function is called before the epoch starts.
		if !val.Status.IsActive() && val.Validator.ActivationEpoch != eth2p0.Epoch(epoch) {
			continue
		}

		resp = append(resp, validator{
			PubKey: pubkey,
			VIdx:   index,
		})
	}

	return resp, nil
}

// waitChainStart blocks until the beacon chain has started.
func waitChainStart(ctx context.Context, eth2Cl eth2wrap.Client, clock clockwork.Clock) {
	for i := 0; ctx.Err() == nil; i++ {
		genesis, err := eth2Cl.Genesis(ctx, &eth2api.GenesisOpts{})
		if err != nil {
			log.Error(ctx, "Failed to fetch genesis information from beacon node. Check beacon node connectivity and API availability", err)
			clock.Sleep(expbackoff.Backoff(expbackoff.FastConfig, i))

			continue
		}

		genesisTime := genesis.Data.GenesisTime

		now := clock.Now()
		if now.Before(genesisTime) {
			delta := genesisTime.Sub(now)
			log.Info(ctx, "Sleeping until genesis time", z.Str("genesisTime", genesisTime.String()), z.Str("sleep", delta.String()))
			clock.Sleep(delta)

			continue
		}

		return
	}
}

// waitBeaconSync blocks until the beacon node is synced.
func waitBeaconSync(ctx context.Context, eth2Cl eth2wrap.Client, clock clockwork.Clock) {
	for i := 0; ctx.Err() == nil; i++ {
		eth2Resp, err := eth2Cl.NodeSyncing(ctx, &eth2api.NodeSyncingOpts{})
		if err != nil {
			log.Error(ctx, "Failed to fetch sync state from beacon node. Check beacon node connectivity and ensure it is synced", err)
			clock.Sleep(expbackoff.Backoff(expbackoff.FastConfig, i))

			continue
		}

		state := eth2Resp.Data

		if state.IsSyncing {
			log.Info(ctx, "Waiting for beacon node to sync", z.U64("distance", uint64(state.SyncDistance)))
			clock.Sleep(expbackoff.Backoff(expbackoff.DefaultConfig, i))

			continue
		}

		return
	}
}

// validator is a validator public key and index.
type validator struct {
	PubKey core.PubKey
	VIdx   eth2p0.ValidatorIndex
}

// validators is a list of validators with convenience functions.
type validators []validator

// PubKeyFromIndex is a convenience function that returns the public key for the validator indexes .
func (v validators) PubKeyFromIndex(vIdx eth2p0.ValidatorIndex) (core.PubKey, bool) {
	for _, val := range v {
		if val.VIdx == vIdx {
			return val.PubKey, true
		}
	}

	return "", false
}

// Indexes is a convenience function that extracts the validator indexes from the validators.
func (v validators) Indexes() []eth2p0.ValidatorIndex {
	var resp []eth2p0.ValidatorIndex
	for _, val := range v {
		resp = append(resp, val.VIdx)
	}

	return resp
}
