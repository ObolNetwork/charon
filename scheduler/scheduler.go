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
	"encoding/json"
	"fmt"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/types"
)

type eth2Provider interface {
	eth2client.NodeSyncingProvider
	eth2client.GenesisTimeProvider
	eth2client.ValidatorsProvider
	eth2client.SlotsPerEpochProvider
	eth2client.SlotDurationProvider
	eth2client.AttesterDutiesProvider
	eth2client.ProposerDutiesProvider
}

func New(manifest types.Manifest, eth2Svc eth2client.Service) (*Scheduler, error) {
	eth2Cl, ok := eth2Svc.(eth2Provider)
	if !ok {
		return nil, errors.New("invalid eth2 client service")
	}

	return &Scheduler{
		eth2Cl:   eth2Cl,
		manifest: manifest,
		quit:     make(chan struct{}),
		duties:   make(map[types.Duty]types.DutyArgSet),
	}, nil
}

type Scheduler struct {
	eth2Cl   eth2Provider
	manifest types.Manifest
	quit     chan struct{}

	duties map[types.Duty]types.DutyArgSet
	subs   []func(context.Context, types.Duty, types.DutyArgSet) error
}

// Subscribe registers a callback for triggering a duty.
// Note this should be called BEFORE Start.
func (s *Scheduler) Subscribe(fn func(context.Context, types.Duty, types.DutyArgSet) error) {
	s.subs = append(s.subs, fn)
}

func (s *Scheduler) Stop() {
	close(s.quit)
}

// Run blocks and runs the scheduler until Stop is called.
func (s *Scheduler) Run() error {
	ctx := log.WithTopic(context.Background(), "sched")

	waitChainStart(ctx, s.eth2Cl)
	waitBeaconSync(ctx, s.eth2Cl)

	slotTicker, err := newSlotTicker(ctx, s.eth2Cl)
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

			err := s.scheduleSlot(slotCtx, slot)
			if err != nil {
				log.Error(ctx, "Scheduling slot error", err)
			}
		}
	}
}

func (s *Scheduler) scheduleSlot(ctx context.Context, slot slot) error {
	if slot.Initial {
		err := s.resolveDuties(ctx, slot)
		if err != nil {
			return err
		}
	}

	for _, dutyType := range types.AllDutyTypes() {
		duty := types.Duty{
			Slot: slot.Slot,
			Type: dutyType,
		}

		dvs, ok := s.duties[duty]
		if !ok {
			// Nothing for this duty.
			continue
		}

		for _, sub := range s.subs {
			err := sub(ctx, duty, dvs)
			if err != nil {
				// TODO(corver): Improve error handling; possibly call subscription async
				//  with backoff until duty expires.
				return err
			}
		}

		delete(s.duties, duty)
	}

	if slot.IsLastInEpoch() {
		err := s.resolveDuties(ctx, slot.Next())
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Scheduler) resolveDuties(ctx context.Context, slot slot) error {
	dvs, indexes, err := resolveActiveDVs(ctx, s.eth2Cl, s.manifest, slot.Slot)
	if err != nil {
		return err
	}

	if len(dvs) == 0 {
		log.Debug(ctx, "No active DVs for slot")
		return nil
	}

	// Resolve attester duties
	{
		attDuties, err := s.eth2Cl.AttesterDuties(ctx, slot.Epoch(), indexes)
		if err != nil {
			return err
		}

		for _, attDuty := range attDuties {
			if attDuty.Slot < eth2p0.Slot(slot.Slot) {
				// Skip duties for earlier slots in initial epoch.
				continue
			}

			b, err := json.Marshal(attDuty)
			if err != nil {
				return errors.Wrap(err, "unmarshal duty")
			}

			duty := types.Duty{Slot: int64(attDuty.Slot), Type: types.DutyAttester}

			argSet, ok := s.duties[duty]
			if !ok {
				argSet = make(types.DutyArgSet)
			}
			argSet[types.VIdx(attDuty.ValidatorIndex)] = b
			s.duties[duty] = argSet

			log.Debug(ctx, "Resolved attester duty",
				z.I64("slot", duty.Slot),
				z.U64("vidx", uint64(attDuty.ValidatorIndex)),
				z.U64("commidx", uint64(attDuty.CommitteeIndex)))
		}
	}

	// Resolve proposer duties
	//{
	//	propDuties, err := s.eth2Cl.ProposerDuties(ctx, slot.Epoch(), indexes)
	//	if err != nil {
	//		return err
	//	}
	//
	//	argSet := make(types.DutyArgSet)
	//	for _, propDuty := range propDuties {
	//		b, err := json.Marshal(propDuty)
	//		if err != nil {
	//			return err
	//		}
	//
	//		argSet[types.VIdx(propDuty.ValidatorIndex)] = b
	//	}
	//
	//	duty := types.Duty{
	//		Slot: slot.Slot,
	//		Type: types.DutyProposer,
	//	}
	//	s.duties[duty] = argSet
	//}

	return nil
}

type slot struct {
	Slot          int64
	Time          time.Time
	Initial       bool
	SlotsPerEpoch int64
	SlotDuration  time.Duration
}

func (s slot) Next() slot {
	return slot{
		Slot:          s.Slot + 1,
		Time:          s.Time.Add(s.SlotDuration),
		Initial:       false,
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
func newSlotTicker(ctx context.Context, eth2Cl eth2Provider) (<-chan slot, error) {
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

	chainAge := time.Since(genesis)
	height := int64(chainAge / slotDuration)
	startTime := genesis.Add(time.Duration(height) * slotDuration)
	initial := true

	resp := make(chan slot)

	go func() {
		for {
			resp <- slot{
				Slot:          height,
				Time:          startTime,
				Initial:       initial,
				SlotsPerEpoch: int64(slotsPerEpoch),
				SlotDuration:  slotDuration,
			}
			height++
			startTime = startTime.Add(slotDuration)
			initial = false

			time.Sleep(time.Until(startTime))
		}
	}()

	return resp, nil
}

// resolveActiveDVs returns the active validators for the slot (in two different formats).
func resolveActiveDVs(ctx context.Context, eth2Cl eth2Provider,
	manifest types.Manifest, slot int64,
) ([]types.VIdx, []eth2p0.ValidatorIndex, error) {
	var pubkeys []eth2p0.BLSPubKey
	for _, dv := range manifest.DVs {
		b, err := dv.PublicKey.MarshalBinary()
		if err != nil {
			return nil, nil, errors.Wrap(err, "marshal pubkey")
		}

		var e2pk eth2p0.BLSPubKey
		n := copy(e2pk[:], b)
		if n != 48 {
			return nil, nil, errors.New("invalid pubkey")
		}

		pubkeys = append(pubkeys, e2pk)
	}

	state := fmt.Sprint(slot)
	if slot == 0 {
		state = "head"
	}

	vals, err := eth2Cl.ValidatorsByPubKey(ctx, state, pubkeys)
	if err != nil {
		return nil, nil, err
	}

	var (
		resp1 []types.VIdx
		resp2 []eth2p0.ValidatorIndex
	)
	for index, validator := range vals {
		if !validator.Status.IsActive() {
			log.Debug(ctx, "skipping inactive validator", z.U64("index", uint64(index)))
			continue
		}

		// TODO(corver): Ensure returned validator in manifest
		resp1 = append(resp1, types.VIdx(index))
		resp2 = append(resp2, index)
	}

	return resp1, resp2, nil
}

func waitChainStart(ctx context.Context, eth2Cl eth2Provider) {
	for {
		genesis, err := eth2Cl.GenesisTime(ctx)
		if err != nil {
			log.Error(ctx, "failure getting genesis time", err)
			time.Sleep(time.Second * 5) // TODO(corver): Improve backoff

			continue
		}

		if time.Now().Before(genesis) {
			delta := time.Since(genesis)
			log.Info(ctx, "Sleeping until genesis time",
				z.Str("genesis", genesis.String()), z.Str("sleep", delta.String()))
			time.Sleep(delta)

			continue
		}

		return
	}
}

func waitBeaconSync(ctx context.Context, eth2Cl eth2Provider) {
	for {
		state, err := eth2Cl.NodeSyncing(ctx)
		if err != nil {
			log.Error(ctx, "failure getting sync state", err)
			time.Sleep(time.Second * 5) // TODO(corver): Improve backoff

			continue
		}

		if state.IsSyncing {
			log.Info(ctx, "Waiting for beacon node to sync",
				z.U64("distance", uint64(state.SyncDistance)))
			time.Sleep(time.Minute) // TODO(corver): Improve backoff

			continue
		}

		return
	}
}
