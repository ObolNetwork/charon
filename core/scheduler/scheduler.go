// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scheduler

import (
	"context"
	"fmt"
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
		resolvedEpoch: -1,
	}, nil
}

type Scheduler struct {
	eth2Cl  eth2Provider
	pubkeys []core.PubKey
	quit    chan struct{}
	clock   clockwork.Clock

	resolvedEpoch int64
	duties        map[core.Duty]core.FetchArgSet
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

// scheduleSlot resolves upcoming duties and triggers resolved duties for the slot.
func (s *Scheduler) scheduleSlot(ctx context.Context, slot slot) error {
	if s.resolvedEpoch != int64(slot.Epoch()) {
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

		argSet, ok := s.duties[duty]
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
		delete(s.duties, duty)
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

			argSet, ok := s.duties[duty]
			if !ok {
				argSet = make(core.FetchArgSet)
			}

			pubkey, ok := vals.PubKeyFromIndex(attDuty.ValidatorIndex)
			if !ok {
				log.Warn(ctx, "ignoring unexpected attester duty", z.U64("vidx", uint64(attDuty.ValidatorIndex)))
				continue
			} else if _, ok := argSet[pubkey]; ok {
				log.Debug(ctx, "Ignoring previously resolved duty", z.Any("duty", duty))
				continue
			}

			argSet[pubkey] = arg
			s.duties[duty] = argSet

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

			argSet, ok := s.duties[duty]
			if !ok {
				argSet = make(core.FetchArgSet)
			}

			pubkey, ok := vals.PubKeyFromIndex(proDuty.ValidatorIndex)
			if !ok {
				log.Warn(ctx, "ignoring unexpected proposer duty", z.U64("vidx", uint64(proDuty.ValidatorIndex)))
				continue
			} else if _, ok := argSet[pubkey]; ok {
				log.Debug(ctx, "Ignoring previously resolved duty", z.Any("duty", duty))
				continue
			}

			argSet[pubkey] = arg
			s.duties[duty] = argSet

			log.Debug(ctx, "Resolved proposer duty",
				z.U64("epoch", uint64(slot.Epoch())),
				z.U64("vidx", uint64(proDuty.ValidatorIndex)),
				z.U64("slot", uint64(proDuty.Slot)),
				z.Any("pubkey", pubkey))
		}
	}

	s.resolvedEpoch = int64(slot.Epoch())

	return nil
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
