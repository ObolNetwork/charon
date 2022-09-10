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

package scheduler

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

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
func New(pubkeys []core.PubKey, eth2Cl eth2wrap.Client, builderAPI bool) (*Scheduler, error) {
	return &Scheduler{
		eth2Cl:  eth2Cl,
		pubkeys: pubkeys,
		quit:    make(chan struct{}),
		duties:  make(map[core.Duty]core.DutyDefinitionSet),
		clock:   clockwork.NewRealClock(),
		delayFunc: func(_ core.Duty, deadline time.Time) <-chan time.Time {
			return time.After(time.Until(deadline))
		},
		resolvedEpoch: math.MaxUint64,
		builderAPI:    builderAPI,
	}, nil
}

type Scheduler struct {
	eth2Cl        eth2wrap.Client
	pubkeys       []core.PubKey
	quit          chan struct{}
	clock         clockwork.Clock
	delayFunc     delayFunc
	resolvedEpoch uint64
	duties        map[core.Duty]core.DutyDefinitionSet
	dutiesMutex   sync.Mutex
	dutySubs      []func(context.Context, core.Duty, core.DutyDefinitionSet) error
	slotSubs      []func(context.Context, core.Slot) error
	builderAPI    bool
}

// SubscribeDuties subscribes a callback function for triggered duties.
// Note this should be called *before* Start.
func (s *Scheduler) SubscribeDuties(fn func(context.Context, core.Duty, core.DutyDefinitionSet) error) {
	s.dutySubs = append(s.dutySubs, fn)
}

// SubscribeSlots subscribes a callback function for triggered slots.
// Note this should be called *before* Start.
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
			slotCtx := log.WithCtx(ctx, z.I64("slot", slot.Slot))
			log.Debug(slotCtx, "Slot ticked")

			instrumentSlot(slot)

			go s.emitCoreSlot(slotCtx, slot)

			s.scheduleSlot(slotCtx, slot)
		}
	}
}

// emitCoreSlot calls all slot subscriptions with the provided slot.
func (s *Scheduler) emitCoreSlot(ctx context.Context, slot core.Slot) {
	for _, sub := range s.slotSubs {
		err := sub(ctx, slot)
		if err != nil {
			log.Error(ctx, "Emit scheduled slot event", err)
		}
	}
}

// GetDutyDefinition returns the definition for a duty if resolved already, otherwise an error.
func (s *Scheduler) GetDutyDefinition(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
	if duty.Type == core.DutyBuilderProposer && !s.builderAPI {
		return nil, errors.New("builder-api not enabled, but duty builder proposer requested")
	} else if duty.Type == core.DutyProposer && s.builderAPI {
		return nil, errors.New("builder-api enabled, but duty proposer requested")
	}

	slotsPerEpoch, err := s.eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return nil, err
	}

	epoch := uint64(duty.Slot) / slotsPerEpoch
	if !s.isEpochResolved(epoch) {
		return nil, errors.New("epoch not resolved yet")
	}

	defSet, ok := s.getDutyDefinitionSet(duty)
	if !ok {
		return nil, errors.New("duty not resolved although epoch is resolved",
			z.Any("duty", duty), z.U64("epoch", epoch))
	}

	return defSet.Clone() // Clone before returning.
}

// scheduleSlot resolves upcoming duties and triggers resolved duties for the slot.
func (s *Scheduler) scheduleSlot(ctx context.Context, slot core.Slot) {
	if s.getResolvedEpoch() != uint64(slot.Epoch()) {
		err := s.resolveDuties(ctx, slot)
		if err != nil {
			log.Warn(ctx, "Resolving duties error (retrying next slot)", err)
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
			ctx = log.WithCtx(ctx, z.Any("duty", duty))
			ctx, span := core.StartDutyTrace(ctx, duty, "core/scheduler.scheduleSlot")
			defer span.End()

			for _, sub := range s.dutySubs {
				clone, err := defSet.Clone() // Clone for each subscriber.
				if err != nil {
					log.Error(ctx, "Cloning duty definition set", err)
					return
				}

				if err := sub(ctx, duty, clone); err != nil {
					log.Error(ctx, "Trigger duty subscriber error", err)
				}
			}
		}()
	}

	if slot.LastInEpoch() {
		err := s.resolveDuties(ctx, slot.Next())
		if err != nil {
			log.Warn(ctx, "Resolving duties error (retrying next slot)", err)
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
	vals, err := resolveActiveValidators(ctx, s.eth2Cl, s.pubkeys, slot.Slot)
	if err != nil {
		return err
	}

	activeGauge.Set(float64(len(vals)))

	if len(vals) == 0 {
		log.Info(ctx, "No active DVs for slot", z.I64("slot", slot.Slot))
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

	s.setResolvedEpoch(uint64(slot.Epoch()))

	return nil
}

// resolveAttDuties resolves attester duties for the given validators.
func (s *Scheduler) resolveAttDuties(ctx context.Context, slot core.Slot, vals validators) error {
	attDuties, err := s.eth2Cl.AttesterDuties(ctx, eth2p0.Epoch(slot.Epoch()), vals.Indexes())
	if err != nil {
		return err
	}

	remaining := make(map[eth2p0.ValidatorIndex]bool)
	for _, index := range vals.Indexes() {
		remaining[index] = true
	}

	for _, attDuty := range attDuties {
		delete(remaining, attDuty.ValidatorIndex)

		if attDuty.Slot < eth2p0.Slot(slot.Slot) {
			// Skip duties for earlier slots in initial epoch.
			continue
		}

		duty := core.NewAttesterDuty(int64(attDuty.Slot))

		pubkey, ok := vals.PubKeyFromIndex(attDuty.ValidatorIndex)
		if !ok {
			log.Warn(ctx, "Ignoring unexpected attester duty", nil, z.U64("vidx", uint64(attDuty.ValidatorIndex)))
			continue
		}

		if !s.setDutyDefinition(duty, pubkey, core.NewAttesterDefinition(attDuty)) {
			continue
		}

		attCtx := log.WithCtx(ctx,
			z.U64("epoch", uint64(slot.Epoch())),
			z.U64("vidx", uint64(attDuty.ValidatorIndex)),
			z.U64("slot", uint64(attDuty.Slot)),
			z.U64("commidx", uint64(attDuty.CommitteeIndex)),
			z.Any("pubkey", pubkey))

		log.Info(attCtx, "Resolved attester duty")

		// Also schedule DutyAggregator.
		duty = core.NewAggregatorDuty(int64(attDuty.Slot))
		if !s.setDutyDefinition(duty, pubkey, core.NewDefinition()) {
			log.Info(attCtx, "Couldn't schedule attestation aggregator duty")
		}

		log.Info(attCtx, "Scheduled attestation aggregator duty")
	}

	if len(remaining) > 0 {
		log.Warn(ctx, "Missing attester duties", nil,
			z.U64("epoch", uint64(slot.Epoch())),
			z.Any("validator_indexes", remaining))
	}

	return nil
}

// resolveProposerDuties resolves proposer duties for the given validators.
func (s *Scheduler) resolveProDuties(ctx context.Context, slot core.Slot, vals validators) error {
	proDuties, err := s.eth2Cl.ProposerDuties(ctx, eth2p0.Epoch(slot.Epoch()), vals.Indexes())
	if err != nil {
		return err
	}

	for _, proDuty := range proDuties {
		if proDuty.Slot < eth2p0.Slot(slot.Slot) {
			// Skip duties for earlier slots in initial epoch.
			continue
		}

		var duty core.Duty

		if s.builderAPI {
			duty = core.Duty{Slot: int64(proDuty.Slot), Type: core.DutyBuilderProposer}
		} else {
			duty = core.Duty{Slot: int64(proDuty.Slot), Type: core.DutyProposer}
		}

		pubkey, ok := vals.PubKeyFromIndex(proDuty.ValidatorIndex)
		if !ok {
			log.Warn(ctx, "Ignoring unexpected proposer duty", nil, z.U64("vidx", uint64(proDuty.ValidatorIndex)))
			continue
		}

		if !s.setDutyDefinition(duty, pubkey, core.NewProposerDefinition(proDuty)) {
			continue
		}

		log.Info(ctx, "Resolved proposer duty",
			z.U64("epoch", uint64(slot.Epoch())),
			z.U64("vidx", uint64(proDuty.ValidatorIndex)),
			z.U64("slot", uint64(proDuty.Slot)),
			z.Any("pubkey", pubkey))
	}

	return nil
}

func (s *Scheduler) getDutyDefinitionSet(duty core.Duty) (core.DutyDefinitionSet, bool) {
	s.dutiesMutex.Lock()
	defer s.dutiesMutex.Unlock()

	defSet, ok := s.duties[duty]

	return defSet, ok
}

func (s *Scheduler) setDutyDefinition(duty core.Duty, pubkey core.PubKey, set core.DutyDefinition) bool {
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

	return true
}

// deleteDuty deletes the duty from the cache.
// TODO(corver): Call this on duty deadline to trim duties.
//
//nolint:unused
func (s *Scheduler) deleteDuty(duty core.Duty) {
	s.dutiesMutex.Lock()
	defer s.dutiesMutex.Unlock()

	delete(s.duties, duty)
}

func (s *Scheduler) getResolvedEpoch() uint64 {
	s.dutiesMutex.Lock()
	defer s.dutiesMutex.Unlock()

	return s.resolvedEpoch
}

func (s *Scheduler) setResolvedEpoch(epoch uint64) {
	s.dutiesMutex.Lock()
	defer s.dutiesMutex.Unlock()

	s.resolvedEpoch = epoch
}

func (s *Scheduler) isEpochResolved(epoch uint64) bool {
	if s.getResolvedEpoch() == math.MaxUint64 {
		return false
	}

	return s.getResolvedEpoch() >= epoch
}

// newSlotTicker returns a blocking channel that will be populated with new slots in real time.
// It is also populated with the current slot immediately.
func newSlotTicker(ctx context.Context, eth2Cl eth2wrap.Client, clock clockwork.Clock) (<-chan core.Slot, error) {
	genesis, err := eth2Cl.GenesisTime(ctx)
	if err != nil {
		return nil, err
	}

	slotDuration, err := eth2Cl.SlotDuration(ctx)
	if err != nil {
		return nil, err
	}

	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return nil, err
	}

	chainAge := clock.Since(genesis)
	height := int64(chainAge / slotDuration)
	startTime := genesis.Add(time.Duration(height) * slotDuration)

	resp := make(chan core.Slot)

	go func() {
		for {
			resp <- core.Slot{
				Slot:          height,
				Time:          startTime,
				SlotsPerEpoch: int64(slotsPerEpoch),
				SlotDuration:  slotDuration,
			}

			height++
			startTime = startTime.Add(slotDuration)
			delay := startTime.Sub(clock.Now())

			select {
			case <-ctx.Done():
				return
			case <-clock.After(delay):
			}
		}
	}()

	return resp, nil
}

// resolveActiveValidators returns the active validators (including their validator index) for the slot.
func resolveActiveValidators(ctx context.Context, eth2Cl eth2wrap.Client,
	pubkeys []core.PubKey, slot int64,
) (validators, error) {
	var e2pks []eth2p0.BLSPubKey
	for _, pubkey := range pubkeys {
		e2pk, err := pubkey.ToETH2()
		if err != nil {
			return nil, err
		}

		e2pks = append(e2pks, e2pk)
	}

	// Use "head" instead of current slot to mitigate clock skew timing issues.
	// Note this does introduce the risk that the resulting active validators
	// is not for this specific slot.
	// TODO(corver): Explicitly sync with beacon node clock.
	_ = slot

	vals, err := eth2Cl.ValidatorsByPubKey(ctx, "head", e2pks)
	if err != nil {
		return nil, err
	}

	var resp []validator
	for index, val := range vals {
		if !val.Status.IsActive() {
			continue
		}

		pubkey, err := core.PubKeyFromBytes(val.Validator.PublicKey[:])
		if err != nil {
			return nil, err
		}

		instrumentValidator(pubkey, val.Balance)

		resp = append(resp, validator{
			PubKey: pubkey,
			VIdx:   index,
		})
	}

	return resp, nil
}

// waitChainStart blocks until the beacon chain has started.
func waitChainStart(ctx context.Context, eth2Cl eth2wrap.Client, clock clockwork.Clock) {
	for {
		genesis, err := eth2Cl.GenesisTime(ctx)
		if err != nil {
			log.Error(ctx, "Failure getting genesis time", err)
			clock.Sleep(time.Second * 5) // TODO(corver): Improve backoff

			continue
		}

		now := clock.Now()
		if now.Before(genesis) {
			delta := genesis.Sub(now)
			log.Info(ctx, "Sleeping until genesis time",
				z.Str("genesis", genesis.String()), z.Str("sleep", delta.String()))
			clock.Sleep(delta)

			continue
		}

		return
	}
}

// waitBeaconSync blocks until the beacon node is synced.
func waitBeaconSync(ctx context.Context, eth2Cl eth2wrap.Client, clock clockwork.Clock) {
	for {
		state, err := eth2Cl.NodeSyncing(ctx)
		if err != nil {
			log.Error(ctx, "Failure getting sync state", err)
			clock.Sleep(time.Second * 5) // TODO(corver): Improve backoff

			continue
		}

		if state.IsSyncing {
			log.Info(ctx, "Waiting for beacon node to sync",
				z.U64("distance", uint64(state.SyncDistance)))
			clock.Sleep(time.Minute) // TODO(corver): Improve backoff

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
