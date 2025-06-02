// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package scheduler

import (
	"context"
	"math"
	"sort"
	"sync"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
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

// NewForT returns a new scheduler for testing using a fake clock.
func NewForT(t *testing.T, clock clockwork.Clock, delayFunc delayFunc, pubkeys []core.PubKey,
	eth2Cl eth2wrap.Client, builderAPI bool,
) *Scheduler {
	t.Helper()

	s, err := New(pubkeys, eth2Cl, builderAPI)
	require.NoError(t, err)

	s.clock = clock
	s.delayFunc = delayFunc

	return s
}

// New returns a new scheduler.
func New(pubkeys []core.PubKey, eth2Cl eth2wrap.Client, builderEnabled bool) (*Scheduler, error) {
	return &Scheduler{
		eth2Cl:        eth2Cl,
		pubkeys:       pubkeys,
		quit:          make(chan struct{}),
		duties:        make(map[core.Duty]core.DutyDefinitionSet),
		dutiesByEpoch: make(map[uint64][]core.Duty),
		clock:         clockwork.NewRealClock(),
		delayFunc: func(_ core.Duty, deadline time.Time) <-chan time.Time {
			return time.After(time.Until(deadline))
		},
		metricSubmitter: newMetricSubmitter(),
		resolvedEpoch:   math.MaxInt64,
		builderEnabled:  builderEnabled,
	}, nil
}

type Scheduler struct {
	eth2Cl          eth2wrap.Client
	pubkeys         []core.PubKey
	quit            chan struct{}
	clock           clockwork.Clock
	delayFunc       delayFunc
	metricSubmitter metricSubmitter
	resolvedEpoch   uint64
	duties          map[core.Duty]core.DutyDefinitionSet
	dutiesByEpoch   map[uint64][]core.Duty
	dutiesMutex     sync.RWMutex
	dutySubs        []func(context.Context, core.Duty, core.DutyDefinitionSet) error
	slotSubs        []func(context.Context, core.Slot) error
	builderEnabled  bool
}

// SubscribeDuties subscribes a callback function for triggered duties.
// Note this should be called *before* Start.
func (s *Scheduler) SubscribeDuties(fn func(context.Context, core.Duty, core.DutyDefinitionSet) error) {
	s.dutySubs = append(s.dutySubs, fn)
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

// Run blocks and runs the scheduler until Stop is called.
func (s *Scheduler) Run() error {
	ctx := log.WithTopic(context.Background(), "sched")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	waitChainStart(ctx, s.eth2Cl, s.clock)
	waitBeaconSync(ctx, s.eth2Cl, s.clock)

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

// ChainReorgEventHandler is connected to SSE Listener and handles chain reorg events.
func (s *Scheduler) ChainReorgEventHandler(ctx context.Context, epoch eth2p0.Epoch) {
	if featureset.Enabled(featureset.ReorgRefreshDuties) {
		if uint64(epoch) < s.getResolvedEpoch() {
			// Refreshing current epoch duties, because of a chain reorg.
			slot, err := currentSlot(ctx, s.eth2Cl, s.clock)
			if err != nil {
				log.Error(ctx, "Failed to calculate the current slot", err)
			} else {
				s.trimDuties(uint64(epoch))
				s.resolveDuties(ctx, slot)
			}
		}
	} else {
		log.Warn(ctx, "Chain reorg event ignored due to disabled ReorgRefreshDuties feature", nil, z.U64("epoch", uint64(epoch)))
	}
}

// emitCoreSlot calls all slot subscriptions asynchronously with the provided slot.
func (s *Scheduler) emitCoreSlot(ctx context.Context, slot core.Slot) {
	for _, sub := range s.slotSubs {
		go func(sub func(context.Context, core.Slot) error) {
			err := sub(ctx, slot)
			if err != nil {
				log.Error(ctx, "Emit scheduled slot event", err, z.U64("slot", slot.Slot))
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
	if s.getResolvedEpoch() != slot.Epoch() {
		err := s.resolveDuties(ctx, slot)
		if err != nil {
			log.Warn(ctx, "Resolving duties error (retrying next slot)", err, z.U64("slot", slot.Slot))
		}
	}

	for _, dutyType := range core.AllDutyTypes() {
		duty := core.Duty{
			Slot: slot.Slot,
			Type: dutyType,
		}

		defSet, ok := s.getDutyDefinitionSet(duty)
		if !ok {
			// Nothing for this duty.
			continue
		}

		// Trigger duty async
		go func() {
			if !delaySlotOffset(ctx, slot, duty, s.delayFunc) {
				return // context cancelled
			}

			instrumentDuty(duty, defSet)
			dutyCtx := log.WithCtx(ctx, z.Any("duty", duty))
			if duty.Type == core.DutyProposer {
				var span trace.Span
				dutyCtx, span = core.StartDutyTrace(dutyCtx, duty, "core/scheduler.scheduleSlot")
				defer span.End()
			}

			for _, sub := range s.dutySubs {
				clone, err := defSet.Clone() // Clone for each subscriber.
				if err != nil {
					log.Error(dutyCtx, "Cloning duty definition set", err)
					return
				}

				if err := sub(dutyCtx, duty, clone); err != nil {
					log.Error(dutyCtx, "Trigger duty subscriber error", err, z.U64("slot", slot.Slot))
				}
			}
		}()
	}

	if slot.LastInEpoch() {
		err := s.resolveDuties(ctx, slot.Next())
		if err != nil {
			log.Warn(ctx, "Resolving duties error (retrying next slot)", err, z.U64("slot", slot.Slot))
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

// resolveDuties resolves the duties for the slot's epoch, caching the results.
func (s *Scheduler) resolveDuties(ctx context.Context, slot core.Slot) error {
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
	opts := &eth2api.AttesterDutiesOpts{
		Epoch:   eth2p0.Epoch(slot.Epoch()),
		Indices: vals.Indexes(),
	}
	eth2Resp, err := s.eth2Cl.AttesterDuties(ctx, opts)
	if err != nil {
		return err
	}
	attDuties := eth2Resp.Data

	// Check if any of the attester duties returned are nil.
	for _, duty := range attDuties {
		if duty == nil {
			return errors.New("attester duty cannot be nil")
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
			log.Warn(ctx, "Ignoring unexpected attester duty", nil, z.U64("vidx", uint64(attDuty.ValidatorIndex)), z.U64("slot", slot.Slot))
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
		log.Warn(ctx, "Missing attester duties", nil,
			z.U64("slot", slot.Slot),
			z.U64("epoch", slot.Epoch()),
			z.Any("validator_indexes", remaining),
		)
	}

	return nil
}

// resolveProposerDuties resolves proposer duties for the given validators.
func (s *Scheduler) resolveProDuties(ctx context.Context, slot core.Slot, vals validators) error {
	opts := &eth2api.ProposerDutiesOpts{
		Epoch:   eth2p0.Epoch(slot.Epoch()),
		Indices: vals.Indexes(),
	}
	eth2Resp, err := s.eth2Cl.ProposerDuties(ctx, opts)
	if err != nil {
		return err
	}
	proDuties := eth2Resp.Data

	// Check if any of the proposer duties returned are nil.
	for _, duty := range proDuties {
		if duty == nil {
			return errors.New("proposer duty cannot be nil")
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
			log.Warn(ctx, "Ignoring unexpected proposer duty", nil, z.U64("vidx", uint64(proDuty.ValidatorIndex)), z.U64("slot", slot.Slot))
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
	opts := &eth2api.SyncCommitteeDutiesOpts{
		Epoch:   eth2p0.Epoch(slot.Epoch()),
		Indices: vals.Indexes(),
	}
	eth2Resp, err := s.eth2Cl.SyncCommitteeDuties(ctx, opts)
	if err != nil {
		return err
	}
	duties := eth2Resp.Data

	// Check if any of the sync committee duties returned are nil.
	for _, duty := range duties {
		if duty == nil {
			return errors.New("sync committee duty cannot be nil")
		}
	}

	for _, syncCommDuty := range duties {
		vIdx := syncCommDuty.ValidatorIndex
		pubkey, ok := vals.PubKeyFromIndex(vIdx)
		if !ok {
			log.Warn(ctx, "Ignoring unexpected sync committee duty", nil, z.U64("vidx", uint64(vIdx)), z.U64("slot", slot.Slot))
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
}

// currentSlot calculates the current slot based on the genesis time and slot duration.
func currentSlot(ctx context.Context, eth2Cl eth2wrap.Client, clock clockwork.Clock) (core.Slot, error) {
	genesisTime, err := eth2wrap.FetchGenesisTime(ctx, eth2Cl)
	if err != nil {
		return core.Slot{}, err
	}
	slotDuration, slotsPerEpoch, err := eth2wrap.FetchSlotsConfig(ctx, eth2Cl)
	if err != nil {
		return core.Slot{}, err
	}

	chainAge := clock.Since(genesisTime)
	slot := int64(chainAge / slotDuration)
	startTime := genesisTime.Add(time.Duration(slot) * slotDuration)

	return core.Slot{
		Slot:          uint64(slot),
		Time:          startTime,
		SlotsPerEpoch: slotsPerEpoch,
		SlotDuration:  slotDuration,
	}, nil
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
			return nil, errors.New("validator data cannot be nil")
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
			log.Error(ctx, "Failure getting genesis", err)
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
			log.Error(ctx, "Failure getting sync state", err)
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
