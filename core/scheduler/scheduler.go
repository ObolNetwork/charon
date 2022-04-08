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
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

// eth2Provider defines the eth2 provider subset used by this package.
type eth2Provider interface {
	eth2client.NodeSyncingProvider
	eth2client.GenesisTimeProvider
	eth2client.ValidatorsProvider
	eth2client.SlotsPerEpochProvider
	eth2client.SlotDurationProvider
	eth2client.AttesterDutiesProvider
	eth2client.ProposerDutiesProvider
}

// NewForT returns a new scheduler for testing supporting a fake clock.
func NewForT(t *testing.T, clock clockwork.Clock, pubkeys []core.PubKey, eth2Svc eth2client.Service) *Scheduler {
	t.Helper()

	s, err := New(pubkeys, eth2Svc)
	require.NoError(t, err)

	s.clock = clock

	return s
}

// New returns a new scheduler.
func New(pubkeys []core.PubKey, eth2Svc eth2client.Service) (*Scheduler, error) {
	eth2Cl, ok := eth2Svc.(eth2Provider)
	if !ok {
		return nil, errors.New("invalid eth2 client service")
	}

	return &Scheduler{
		eth2Cl:        eth2Cl,
		pubkeys:       pubkeys,
		quit:          make(chan struct{}),
		duties:        make(map[core.Duty]core.FetchArgSet),
		clock:         clockwork.NewRealClock(),
		resolvedEpoch: math.MaxUint64,
	}, nil
}

type Scheduler struct {
	eth2Cl  eth2Provider
	pubkeys []core.PubKey
	quit    chan struct{}
	clock   clockwork.Clock

	resolvedEpoch uint64
	duties        map[core.Duty]core.FetchArgSet
	dutiesMutex   sync.Mutex
	subs          []func(context.Context, core.Duty, core.FetchArgSet) error
}

// Subscribe registers a callback for triggering a duty.
// Note this should be called *before* Start.
func (s *Scheduler) Subscribe(fn func(context.Context, core.Duty, core.FetchArgSet) error) {
	s.subs = append(s.subs, fn)
}

func (s *Scheduler) Stop() {
	close(s.quit)
}

// Run blocks and runs the scheduler until Stop is called.
func (s *Scheduler) Run() error {
	ctx := log.WithTopic(context.Background(), "sched")

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

			err := s.scheduleSlot(slotCtx, slot)
			if err != nil {
				log.Error(ctx, "Scheduling slot error", err)
			}
		}
	}
}

// GetDuty returns the argSet for a duty if resolved already, otherwise an error.
func (s *Scheduler) GetDuty(ctx context.Context, duty core.Duty) (core.FetchArgSet, error) {
	slotsPerEpoch, err := s.eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return nil, err
	}

	epoch := uint64(duty.Slot) / slotsPerEpoch
	if !s.isEpochResolved(epoch) {
		return nil, errors.New("epoch not resolved yet")
	}

	argSet, ok := s.getFetchArgSet(duty)
	if !ok {
		return nil, errors.New("duty not resolved although epoch is marked as resolved")
	}

	return argSet, nil
}

// scheduleSlot resolves upcoming duties and triggers resolved duties for the slot.
func (s *Scheduler) scheduleSlot(ctx context.Context, slot slot) error {
	if s.getResolvedEpoch() != uint64(slot.Epoch()) {
		err := s.resolveDuties(ctx, slot)
		if err != nil {
			log.Warn(ctx, "Resolving duties error (retrying next slot)", z.Err(err))
		}
	}

	for _, dutyType := range core.AllDutyTypes() {
		duty := core.Duty{
			Slot: slot.Slot,
			Type: dutyType,
		}

		argSet, ok := s.getFetchArgSet(duty)
		if !ok {
			// Nothing for this duty.
			continue
		}

		instrumentDuty(duty, argSet)

		ctx, span := core.StartDutyTrace(ctx, duty, "core/scheduler.scheduleSlot")

		for _, sub := range s.subs {
			err := sub(ctx, duty, argSet)
			if err != nil {
				// TODO(corver): Improve error handling; possibly call subscription async
				//  with backoff until duty expires.
				span.End()
				return err
			}
		}

		span.End()
		// TODO(leo): This had to be commented out because the scheduler doesn't need the duty anymore,
		// but the validatorAPI will need the duty when verifying a randao. Solved when we have the shared
		// component to resolve duties.
		// s.deleteDuty(duty)
	}

	if slot.IsLastInEpoch() {
		err := s.resolveDuties(ctx, slot.Next())
		if err != nil {
			log.Warn(ctx, "Resolving duties error (retrying next slot)", z.Err(err))
		}
	}

	return nil
}

// resolveDuties resolves the duties for the slot's epoch, caching the results.
func (s *Scheduler) resolveDuties(ctx context.Context, slot slot) error {
	vals, err := resolveActiveValidators(ctx, s.eth2Cl, s.pubkeys, slot.Slot)
	if err != nil {
		return err
	}

	if len(vals) == 0 {
		log.Debug(ctx, "No active DVs for slot", z.I64("slot", slot.Slot))
		return nil
	}

	// Resolve attester duties
	{
		attDuties, err := s.eth2Cl.AttesterDuties(ctx, slot.Epoch(), vals.Indexes())
		if err != nil {
			return err
		}

		// TODO(corver): Log when duty not included for some indexes

		for _, attDuty := range attDuties {
			if attDuty.Slot < eth2p0.Slot(slot.Slot) {
				// Skip duties for earlier slots in initial epoch.
				continue
			}

			arg, err := core.EncodeAttesterFetchArg(attDuty)
			if err != nil {
				return errors.Wrap(err, "encode attester duty")
			}

			duty := core.Duty{Slot: int64(attDuty.Slot), Type: core.DutyAttester}

			pubkey, ok := vals.PubKeyFromIndex(attDuty.ValidatorIndex)
			if !ok {
				log.Warn(ctx, "ignoring unexpected attester duty", z.U64("vidx", uint64(attDuty.ValidatorIndex)))
				continue
			}

			if !s.setFetchArg(duty, pubkey, arg) {
				log.Debug(ctx, "Ignoring previously resolved duty", z.Any("duty", duty))
				continue
			}

			log.Debug(ctx, "Resolved attester duty",
				z.U64("epoch", uint64(slot.Epoch())),
				z.U64("vidx", uint64(attDuty.ValidatorIndex)),
				z.U64("slot", uint64(attDuty.Slot)),
				z.U64("commidx", uint64(attDuty.CommitteeIndex)),
				z.Any("pubkey", pubkey))
		}
	}

	// resolve proposer duties
	{
		proDuties, err := s.eth2Cl.ProposerDuties(ctx, slot.Epoch(), vals.Indexes())
		if err != nil {
			return err
		}

		for _, proDuty := range proDuties {
			if proDuty.Slot < eth2p0.Slot(slot.Slot) {
				// Skip duties for earlier slots in initial epoch.
				continue
			}

			arg, err := core.EncodeProposerFetchArg(proDuty)
			if err != nil {
				return errors.Wrap(err, "encode proposer duty")
			}

			duty := core.Duty{Slot: int64(proDuty.Slot), Type: core.DutyProposer}

			pubkey, ok := vals.PubKeyFromIndex(proDuty.ValidatorIndex)
			if !ok {
				log.Warn(ctx, "ignoring unexpected proposer duty", z.U64("vidx", uint64(proDuty.ValidatorIndex)))
				continue
			}

			if !s.setFetchArg(duty, pubkey, arg) {
				log.Debug(ctx, "Ignoring previously resolved duty", z.Any("duty", duty))
				continue
			}

			log.Debug(ctx, "Resolved proposer duty",
				z.U64("epoch", uint64(slot.Epoch())),
				z.U64("vidx", uint64(proDuty.ValidatorIndex)),
				z.U64("slot", uint64(proDuty.Slot)),
				z.Any("pubkey", pubkey))
		}
	}

	s.setResolvedEpoch(uint64(slot.Epoch()))

	return nil
}

func (s *Scheduler) getFetchArgSet(duty core.Duty) (core.FetchArgSet, bool) {
	s.dutiesMutex.Lock()
	defer s.dutiesMutex.Unlock()

	argSet, ok := s.duties[duty]

	return argSet, ok
}

func (s *Scheduler) setFetchArg(duty core.Duty, pubkey core.PubKey, set core.FetchArg) bool {
	s.dutiesMutex.Lock()
	defer s.dutiesMutex.Unlock()

	argSet, ok := s.duties[duty]
	if !ok {
		argSet = make(core.FetchArgSet)
	}
	if _, ok := argSet[pubkey]; ok {
		return false
	}

	argSet[pubkey] = set
	s.duties[duty] = argSet

	return true
}

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
	return s.getResolvedEpoch() >= epoch
}

// slot is a beacon chain slot and includes chain metadata to infer epoch and next slot.
type slot struct {
	Slot          int64
	Time          time.Time
	SlotsPerEpoch int64
	SlotDuration  time.Duration
}

func (s slot) Next() slot {
	return slot{
		Slot:          s.Slot + 1,
		Time:          s.Time.Add(s.SlotDuration),
		SlotsPerEpoch: s.SlotsPerEpoch,
		SlotDuration:  s.SlotDuration,
	}
}

func (s slot) Epoch() eth2p0.Epoch {
	return eth2p0.Epoch(s.Slot / s.SlotsPerEpoch)
}

func (s slot) IsLastInEpoch() bool {
	return s.Slot%s.SlotsPerEpoch == s.SlotsPerEpoch-1
}

// newSlotTicker returns a blocking channel that will be populated with new slots in real time.
// It is also populated with the current slot immediately.
func newSlotTicker(ctx context.Context, eth2Cl eth2Provider, clock clockwork.Clock) (<-chan slot, error) {
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

	resp := make(chan slot)

	go func() {
		for {
			resp <- slot{
				Slot:          height,
				Time:          startTime,
				SlotsPerEpoch: int64(slotsPerEpoch),
				SlotDuration:  slotDuration,
			}
			height++
			startTime = startTime.Add(slotDuration)

			clock.Sleep(startTime.Sub(clock.Now()))
		}
	}()

	return resp, nil
}

// resolveActiveValidators returns the active validators (including their validator index) for the slot.
func resolveActiveValidators(ctx context.Context, eth2Cl eth2Provider,
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

	state := fmt.Sprint(slot)
	if slot == 0 {
		state = "head"
	}

	vals, err := eth2Cl.ValidatorsByPubKey(ctx, state, e2pks)
	if err != nil {
		return nil, err
	}

	var resp []validator
	for index, val := range vals {
		if !val.Status.IsActive() {
			log.Debug(ctx, "skipping inactive validator", z.U64("index", uint64(index)))
			continue
		}

		pubkey, err := core.PubKeyFromBytes(val.Validator.PublicKey[:])
		if err != nil {
			return nil, err
		}

		resp = append(resp, validator{
			PubKey: pubkey,
			VIdx:   index,
		})
	}

	return resp, nil
}

// waitChainStart blocks until the beacon chain has started.
func waitChainStart(ctx context.Context, eth2Cl eth2Provider, clock clockwork.Clock) {
	for {
		genesis, err := eth2Cl.GenesisTime(ctx)
		if err != nil {
			log.Error(ctx, "failure getting genesis time", err)
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
func waitBeaconSync(ctx context.Context, eth2Cl eth2Provider, clock clockwork.Clock) {
	for {
		state, err := eth2Cl.NodeSyncing(ctx)
		if err != nil {
			log.Error(ctx, "failure getting sync state", err)
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
