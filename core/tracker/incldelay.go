// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tracker

import (
	"context"
	"fmt"
	"sync"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

// inclDelayLag is the number of slots to lag before calculating inclusion delay.
// Half an epoch is good compromise between finality and small gaps on startup.
const (
	inclDelayLag    = 16
	trimEpochOffset = 3
)

// dutiesFunc returns the duty definitions for a given duty.
type dutiesFunc func(context.Context, core.Duty) (core.DutyDefinitionSet, error)

// NewInclusionDelay returns a new inclusion delay tracker.
func NewInclusionDelay(ctx context.Context, eth2Cl eth2wrap.Client, dutiesFunc dutiesFunc) (*InclusionDelay, error) {
	genesisTime, err := eth2Cl.GenesisTime(ctx)
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

	return &InclusionDelay{
		eth2Cl:         eth2Cl,
		dutiesFunc:     dutiesFunc,
		instrumentFunc: instrumentAvgDelay,
		logMappingFunc: logMapping,
		bcastDelays:    make(map[int64]map[eth2p0.Root]time.Duration),
		genesisTime:    genesisTime,
		slotDuration:   slotDuration,
		slotsPerEpoch:  int(slotsPerEpoch),
		clock:          clockwork.NewRealClock(),
	}, nil
}

// InclusionDelay tracks the inclusion delay of attestations.
type InclusionDelay struct {
	eth2Cl         eth2wrap.Client
	dutiesFunc     dutiesFunc
	instrumentFunc func(inclDelaySlots []int64)
	logMappingFunc func(ctx context.Context, slot int64, bcastDelay time.Duration, inclDelay int64)
	genesisTime    time.Time
	slotDuration   time.Duration
	slotsPerEpoch  int
	clock          clockwork.Clock

	mu            sync.Mutex
	bcastDelays   map[int64]map[eth2p0.Root]time.Duration
	dutyStartSlot int64
}

// Broadcasted records the broadcast delay of an attestation.
func (d *InclusionDelay) Broadcasted(slot int64, att core.Attestation) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.bcastDelays[slot]; !ok {
		d.bcastDelays[slot] = make(map[eth2p0.Root]time.Duration)
	}

	d.bcastDelays[slot][att.Data.BeaconBlockRoot] = d.clock.Now().Sub(d.slotStartTime(slot))
}

// Instrument calculates attestation inclusion delay for a block.
//
// Inclusion delay is the average of the distance between the slot a validator’s attestation
// is expected by the network and the slot the attestation is actually included on-chain.
// See https://rated.gitbook.io/rated-documentation/rating-methodologies/ethereum-beacon-chain/network-explorer-definitions/top-screener#inclusion-delay.
func (d *InclusionDelay) Instrument(ctx context.Context, current core.Slot) error {
	// blockSlot the block we want to instrument.
	blockSlot := current.Slot - inclDelayLag

	startSlot, ok := d.getOrSetStartSlot(current.Slot)
	if !ok { // Set start slot.
		return nil
	} else if blockSlot < startSlot {
		return nil // Still need to wait
	}

	atts, err := d.eth2Cl.BlockAttestations(ctx, fmt.Sprint(blockSlot))
	if err != nil {
		return err
	}

	var delays []int64
	for _, att := range atts {
		if att == nil || att.Data == nil {
			return errors.New("attestation fields cannot be nil")
		}

		attSlot := att.Data.Slot
		if int64(attSlot) < startSlot {
			continue
		}

		// Get all our duties for this attestation blockSlot
		set, err := d.dutiesFunc(ctx, core.NewAttesterDuty(int64(attSlot)))
		if errors.Is(err, core.ErrNotFound) {
			continue // No duties for this slot.
		} else if err != nil {
			return err
		}

		// Get all our validator committee indexes for this attestation.
		for _, def := range set {
			duty, ok := def.(core.AttesterDefinition)
			if !ok {
				return errors.New("invalid attester definition")
			}

			if duty.CommitteeIndex != att.Data.Index {
				continue // This duty is for another committee
			}

			if !att.AggregationBits.BitAt(duty.ValidatorCommitteeIndex) {
				continue // We are not included in attestation
				// Note that to track missed attestations, we'd need to keep state of seen attestations.
			}

			inclDelay := blockSlot - int64(attSlot)
			d.logDelayMapping(ctx, int64(attSlot), att, inclDelay)
			delays = append(delays, inclDelay)
		}
	}

	if len(delays) > 0 {
		d.instrumentFunc(delays)
	}

	d.trimBcastDelays(blockSlot - int64(d.slotsPerEpoch*trimEpochOffset))

	return nil
}

func (d *InclusionDelay) slotStartTime(slot int64) time.Time {
	return d.genesisTime.Add(time.Duration(slot) * d.slotDuration)
}

// getOrSetStartSlot returns a previously set duty start slot and true or it sets it and returns false.
func (d *InclusionDelay) getOrSetStartSlot(slot int64) (int64, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.dutyStartSlot == 0 {
		d.dutyStartSlot = slot
		return 0, false
	}

	return d.dutyStartSlot, true
}

// trimBcastDelays deletes all broadcast delays that are older than the given slot.
func (d *InclusionDelay) trimBcastDelays(slot int64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for s := range d.bcastDelays {
		if s <= slot {
			delete(d.bcastDelays, s)
		}
	}
}

// logDelayMapping logs the broadcast delay vs inclusion delay for a given attestation.
// TODO(corver): Find a better less verbose way to track this.
func (d *InclusionDelay) logDelayMapping(ctx context.Context, slot int64, att *eth2p0.Attestation, inclDelay int64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	bcastDelay, ok := d.bcastDelays[slot][att.Data.BeaconBlockRoot]
	if !ok {
		log.Debug(ctx, "Missing broadcast delay found for included attestation", z.Int("slot", int(slot)))
	} else {
		d.logMappingFunc(ctx, slot, bcastDelay, inclDelay)
	}
}

func logMapping(ctx context.Context, slot int64, bcastDelay time.Duration, inclDelay int64) {
	log.Debug(ctx, "Attestation broadcast delay (secs) vs inclusion distance (slots)",
		z.Int("slot", int(slot)),
		z.F64("bcast_delay", bcastDelay.Seconds()),
		z.I64("incl_delay", inclDelay),
	)
}

// instrumentAvgDelay sets the avg inclusion delay metric.
func instrumentAvgDelay(delays []int64) {
	var sum int64
	for _, delay := range delays {
		sum += delay
	}

	avg := sum / int64(len(delays))
	inclusionDelay.Set(float64(avg))
}
