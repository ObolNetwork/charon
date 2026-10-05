// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"context"
	"math"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/eth2wrap"
)

// SlotOffsetFunc returns the offset into the slot at which the duty's data is due, as defined by
// the network spec. It returns zero for duty types without a spec deadline.
//
// Note that the deadlines change at the gloas fork, so offsets are resolved per slot.
type SlotOffsetFunc func(Duty) time.Duration

// NewSlotOffsetFunc returns a function that provides the spec-defined offsets into the slot at
// which duty data is due. The gloas deadlines apply from the gloas epoch of the fork schedule,
// read on each call so that a fork scheduled after startup applies.
func NewSlotOffsetFunc(ctx context.Context, eth2Cl eth2wrap.Client, forkSchedule func() eth2wrap.ForkForkSchedule) (SlotOffsetFunc, error) {
	slotDuration, slotsPerEpoch, err := eth2wrap.FetchSlotsConfig(ctx, eth2Cl)
	if err != nil {
		return nil, err
	}

	timing, err := eth2wrap.FetchSlotTimingConfig(ctx, eth2Cl)
	if err != nil {
		return nil, err
	}

	return newSlotOffsetFunc(slotDuration, slotsPerEpoch, timing, forkSchedule), nil
}

// newSlotOffsetFunc returns a slot offset function for the provided spec values.
func newSlotOffsetFunc(slotDuration time.Duration, slotsPerEpoch uint64, timing eth2wrap.SlotTimingConfig,
	forkSchedule func() eth2wrap.ForkForkSchedule,
) SlotOffsetFunc {
	bpsByDuty := map[DutyType]eth2wrap.ForkBPS{
		DutyAttester:           timing.Attestation,
		DutyAggregator:         timing.Aggregate,
		DutySyncMessage:        timing.SyncMessage,
		DutySyncContribution:   timing.Contribution,
		DutyPayloadAttestation: timing.Payload,
		// A self-built payload envelope is due at the same payload deadline the PTC attests against.
		DutyExecutionPayloadEnvelope: timing.Payload,
	}

	return func(duty Duty) time.Duration {
		bps, ok := bpsByDuty[duty.Type]
		if !ok {
			return 0
		}

		deadline := bps.PreGloas

		gloasSlot, gloasScheduled := forkSlot(gloasEpoch(forkSchedule()), slotsPerEpoch)
		if gloasScheduled && duty.Slot >= gloasSlot {
			deadline = bps.Gloas
		}

		// Round to the nearest millisecond so that the spec's basis point approximations of
		// 1/3 and 2/3 resolve to whole milliseconds, ie. 4s and 8s for a 12s slot duration.
		return (slotDuration * time.Duration(deadline) / eth2wrap.BasisPoints).Round(time.Millisecond)
	}
}

// gloasEpoch returns the gloas epoch of the schedule, math.MaxUint64 if absent.
func gloasEpoch(schedule eth2wrap.ForkForkSchedule) eth2p0.Epoch {
	fs, ok := schedule[eth2wrap.Gloas]
	if !ok {
		return math.MaxUint64
	}

	return fs.Epoch
}

// forkSlot returns the first slot of the fork epoch and true, or false if the fork isn't scheduled.
// Unscheduled forks are published with an epoch of math.MaxUint64, which overflows when
// converted to a slot.
func forkSlot(epoch eth2p0.Epoch, slotsPerEpoch uint64) (uint64, bool) {
	if slotsPerEpoch == 0 || uint64(epoch) > math.MaxUint64/slotsPerEpoch {
		return 0, false
	}

	return uint64(epoch) * slotsPerEpoch, true
}
