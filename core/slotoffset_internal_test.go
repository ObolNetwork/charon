// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
)

// mainnetTiming returns the intra-slot deadlines of a network that schedules the gloas fork at epoch 64.
func mainnetTiming() eth2wrap.SlotTimingConfig {
	return eth2wrap.SlotTimingConfig{
		Attestation:        eth2wrap.ForkBPS{PreGloas: 3333, Gloas: 2500},
		Aggregate:          eth2wrap.ForkBPS{PreGloas: 6667, Gloas: 5000},
		SyncMessage:        eth2wrap.ForkBPS{PreGloas: 3333, Gloas: 2500},
		Contribution:       eth2wrap.ForkBPS{PreGloas: 6667, Gloas: 5000},
		Payload:            eth2wrap.ForkBPS{Gloas: 5000},
		PayloadAttestation: eth2wrap.ForkBPS{Gloas: 7500},
		GloasEpoch:         64,
	}
}

func TestSlotOffsetPayloadAttestation(t *testing.T) {
	offsetFunc := newSlotOffsetFunc(12*time.Second, 16, mainnetTiming())

	const gloasSlot = 64 * 16

	// The payload attestation duty is triggered when the builder's payload is due (1/2 into the
	// slot), not at its own deadline of 3/4 into the slot, so that consensus, partial signature
	// exchange and submission can complete before the deadline.
	require.Equal(t, 6*time.Second, offsetFunc(Duty{Slot: gloasSlot, Type: DutyPayloadAttestation}))

	// The duty doesn't exist before the gloas fork.
	require.Zero(t, offsetFunc(Duty{Slot: gloasSlot - 1, Type: DutyPayloadAttestation}))
}

func TestSlotOffsetPreGloasMatchesFractions(t *testing.T) {
	// A 12 second slot duration must resolve to the exact fractions used before the gloas fork,
	// since 3333 and 6667 basis points are the consensus spec's approximations of 1/3 and 2/3.
	offsetFunc := newSlotOffsetFunc(12*time.Second, 16, mainnetTiming())

	tests := []struct {
		dutyType DutyType
		expect   time.Duration
	}{
		{dutyType: DutyAttester, expect: 4 * time.Second},
		{dutyType: DutyAggregator, expect: 8 * time.Second},
		{dutyType: DutySyncMessage, expect: 4 * time.Second},
		{dutyType: DutySyncContribution, expect: 8 * time.Second},
	}

	for _, test := range tests {
		t.Run(test.dutyType.String(), func(t *testing.T) {
			require.Equal(t, test.expect, offsetFunc(Duty{Slot: 0, Type: test.dutyType}))
		})
	}
}

func TestSlotOffsetGloas(t *testing.T) {
	offsetFunc := newSlotOffsetFunc(12*time.Second, 16, mainnetTiming())

	const gloasSlot = 64 * 16

	tests := []struct {
		dutyType DutyType
		expect   time.Duration
	}{
		{dutyType: DutyAttester, expect: 3 * time.Second},
		{dutyType: DutyAggregator, expect: 6 * time.Second},
		{dutyType: DutySyncMessage, expect: 3 * time.Second},
		{dutyType: DutySyncContribution, expect: 6 * time.Second},
	}

	for _, test := range tests {
		t.Run(test.dutyType.String(), func(t *testing.T) {
			require.Equal(t, test.expect, offsetFunc(Duty{Slot: gloasSlot, Type: test.dutyType}))
		})
	}
}

func TestSlotOffsetForkBoundary(t *testing.T) {
	offsetFunc := newSlotOffsetFunc(12*time.Second, 16, mainnetTiming())

	const gloasSlot = 64 * 16

	// The last slot before the fork still uses the pre-gloas deadline.
	require.Equal(t, 4*time.Second, offsetFunc(Duty{Slot: gloasSlot - 1, Type: DutyAttester}))
	require.Equal(t, 3*time.Second, offsetFunc(Duty{Slot: gloasSlot, Type: DutyAttester}))
}

func TestSlotOffsetGloasNotScheduled(t *testing.T) {
	timing := mainnetTiming()
	timing.GloasEpoch = math.MaxUint64

	offsetFunc := newSlotOffsetFunc(12*time.Second, 16, timing)

	// The gloas slot must not overflow, so even the last possible slot uses the pre-gloas deadline.
	require.Equal(t, 4*time.Second, offsetFunc(Duty{Slot: 0, Type: DutyAttester}))
	require.Equal(t, 4*time.Second, offsetFunc(Duty{Slot: math.MaxUint64, Type: DutyAttester}))
}

func TestSlotOffsetDutiesWithoutDeadline(t *testing.T) {
	offsetFunc := newSlotOffsetFunc(12*time.Second, 16, mainnetTiming())

	// Duties without a spec deadline are triggered at the start of the slot.
	for _, dutyType := range []DutyType{
		DutyProposer, DutyRandao, DutyPrepareAggregator, DutyPrepareSyncContribution,
		DutyBuilderRegistration, DutyExit, DutySignature, DutyInfoSync, DutyUnknown,
	} {
		t.Run(dutyType.String(), func(t *testing.T) {
			require.Zero(t, offsetFunc(Duty{Slot: 0, Type: dutyType}))
		})
	}
}

func TestSlotOffsetShorterSlots(t *testing.T) {
	tests := []struct {
		name         string
		slotDuration time.Duration
		preGloas     time.Duration
		gloas        time.Duration
	}{
		{
			name:         "gnosis",
			slotDuration: 5 * time.Second,
			preGloas:     1667 * time.Millisecond, // 3333 basis points of 5s, rounded to the nearest millisecond.
			gloas:        1250 * time.Millisecond,
		},
		{
			name:         "simnet",
			slotDuration: time.Second,
			preGloas:     333 * time.Millisecond,
			gloas:        250 * time.Millisecond,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			offsetFunc := newSlotOffsetFunc(test.slotDuration, 16, mainnetTiming())

			require.Equal(t, test.preGloas, offsetFunc(Duty{Slot: 0, Type: DutyAttester}))
			require.Equal(t, test.gloas, offsetFunc(Duty{Slot: 64 * 16, Type: DutyAttester}))
		})
	}
}
