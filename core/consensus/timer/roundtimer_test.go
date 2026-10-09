// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package timer_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus/timer"
)

// zeroOffsetFunc is a slot offset function that starts all duties at the start of the slot.
var zeroOffsetFunc core.SlotOffsetFunc = func(core.Duty) time.Duration { return 0 }

// noForkSchedule is a fork schedule function without any scheduled forks.
var noForkSchedule = func() eth2wrap.ForkForkSchedule { return eth2wrap.ForkForkSchedule{} }

const slotsPerEpoch = 32

func TestGetTimerFunc(t *testing.T) {
	// Use zero values for tests to use default clock.Now() behavior
	genesisTime := time.Time{}
	slotDuration := time.Duration(0)

	timerFunc := timer.GetRoundTimerFunc(genesisTime, slotDuration, slotsPerEpoch, zeroOffsetFunc, noForkSchedule)
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(0)).Type())
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(1)).Type())
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(2)).Type())

	featureset.DisableForT(t, featureset.EagerDoubleLinear)

	timerFunc = timer.GetRoundTimerFunc(genesisTime, slotDuration, slotsPerEpoch, zeroOffsetFunc, noForkSchedule)
	require.Equal(t, timer.TimerIncreasing, timerFunc(core.NewAttesterDuty(0)).Type())
	require.Equal(t, timer.TimerIncreasing, timerFunc(core.NewAttesterDuty(1)).Type())
	require.Equal(t, timer.TimerIncreasing, timerFunc(core.NewAttesterDuty(2)).Type())

	featureset.EnableForT(t, featureset.Linear)

	timerFunc = timer.GetRoundTimerFunc(genesisTime, slotDuration, slotsPerEpoch, zeroOffsetFunc, noForkSchedule)
	// non proposer duty, defaults to increasing
	require.Equal(t, timer.TimerIncreasing, timerFunc(core.NewAttesterDuty(0)).Type())
	require.Equal(t, timer.TimerIncreasing, timerFunc(core.NewAttesterDuty(1)).Type())
	require.Equal(t, timer.TimerIncreasing, timerFunc(core.NewAttesterDuty(2)).Type())

	featureset.EnableForT(t, featureset.EagerDoubleLinear)
	// non proposer duty, defaults to eager
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(0)).Type())
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(1)).Type())
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(2)).Type())

	// proposer duty, uses linear
	require.Equal(t, timer.TimerLinear, timerFunc(core.NewProposerDuty(0)).Type())
	require.Equal(t, timer.TimerLinear, timerFunc(core.NewProposerDuty(1)).Type())
	require.Equal(t, timer.TimerLinear, timerFunc(core.NewProposerDuty(2)).Type())
}

func TestGetTimerFuncGloasAttester(t *testing.T) {
	const gloasEpoch = 2

	gloasSlot := uint64(gloasEpoch * slotsPerEpoch)

	var schedule eth2wrap.ForkForkSchedule

	forkSchedule := func() eth2wrap.ForkForkSchedule { return schedule }

	timerFunc := timer.GetRoundTimerFunc(time.Time{}, 0, slotsPerEpoch, zeroOffsetFunc, forkSchedule)

	// Without gloas scheduled, attester duties keep the eager double linear timer.
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(gloasSlot)).Type())

	// Gloas scheduled at runtime applies to attester duties from its first slot.
	schedule = eth2wrap.ForkForkSchedule{eth2wrap.Gloas: {Epoch: gloasEpoch}}

	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(gloasSlot-1)).Type())
	require.Equal(t, timer.TimerEagerAheadSplit, timerFunc(core.NewAttesterDuty(gloasSlot)).Type())
	require.Equal(t, timer.TimerEagerAheadSplit, timerFunc(core.NewAttesterDuty(gloasSlot+1)).Type())

	// Other duties are unaffected by gloas.
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewProposerDuty(gloasSlot)).Type())
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAggregatorDuty(gloasSlot)).Type())

	// The gloas attester timer doesn't depend on the legacy timer features.
	featureset.DisableForT(t, featureset.EagerDoubleLinear)
	featureset.EnableForT(t, featureset.Linear)

	timerFunc = timer.GetRoundTimerFunc(time.Time{}, 0, slotsPerEpoch, zeroOffsetFunc, forkSchedule)
	require.Equal(t, timer.TimerIncreasing, timerFunc(core.NewAttesterDuty(gloasSlot-1)).Type())
	require.Equal(t, timer.TimerEagerAheadSplit, timerFunc(core.NewAttesterDuty(gloasSlot)).Type())
	require.Equal(t, timer.TimerLinear, timerFunc(core.NewProposerDuty(gloasSlot)).Type())
}
