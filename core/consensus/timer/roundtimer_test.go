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

// noProposerTimer is a cluster agreement function never agreeing on a proposer timer.
var noProposerTimer = func(uint64) string { return "" }

const slotsPerEpoch = 32

func TestGetTimerFunc(t *testing.T) {
	// Use zero values for tests to use default clock.Now() behavior
	genesisTime := time.Time{}
	slotDuration := time.Duration(0)

	timerFunc := timer.GetRoundTimerFunc(genesisTime, slotDuration, slotsPerEpoch, zeroOffsetFunc, noForkSchedule, noProposerTimer)
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(0)).Type())
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(1)).Type())
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(2)).Type())

	featureset.DisableForT(t, featureset.EagerDoubleLinear)

	timerFunc = timer.GetRoundTimerFunc(genesisTime, slotDuration, slotsPerEpoch, zeroOffsetFunc, noForkSchedule, noProposerTimer)
	require.Equal(t, timer.TimerIncreasing, timerFunc(core.NewAttesterDuty(0)).Type())
	require.Equal(t, timer.TimerIncreasing, timerFunc(core.NewAttesterDuty(1)).Type())
	require.Equal(t, timer.TimerIncreasing, timerFunc(core.NewAttesterDuty(2)).Type())

	featureset.EnableForT(t, featureset.Linear)

	timerFunc = timer.GetRoundTimerFunc(genesisTime, slotDuration, slotsPerEpoch, zeroOffsetFunc, noForkSchedule, noProposerTimer)
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

func TestGetTimerFuncGloas(t *testing.T) {
	const gloasEpoch = 2

	gloasSlot := uint64(gloasEpoch * slotsPerEpoch)

	var (
		schedule      eth2wrap.ForkForkSchedule
		proposerTimer string
	)

	forkSchedule := func() eth2wrap.ForkForkSchedule { return schedule }
	proposerTimerFunc := func(uint64) string { return proposerTimer }

	timerFunc := timer.GetRoundTimerFunc(time.Time{}, 0, slotsPerEpoch, zeroOffsetFunc, forkSchedule, proposerTimerFunc)

	// Without gloas scheduled, attester duties keep the eager double linear timer.
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(gloasSlot)).Type())

	// Gloas scheduled at runtime applies to attester duties from its first slot.
	schedule = eth2wrap.ForkForkSchedule{eth2wrap.Gloas: {Epoch: gloasEpoch}}

	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(gloasSlot-1)).Type())
	require.Equal(t, timer.TimerEagerAheadSplit, timerFunc(core.NewAttesterDuty(gloasSlot)).Type())
	require.Equal(t, timer.TimerEagerAheadSplit, timerFunc(core.NewAttesterDuty(gloasSlot+1)).Type())

	// Gloas proposer duties keep the timer type, with the gloas re-arm extension and no proposal timeout.
	require.Equal(t, []string{"double_total_on_rearm", "proposal_timeout"}, timerFunc(core.NewProposerDuty(gloasSlot-1)).Extensions())
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewProposerDuty(gloasSlot)).Type())
	require.Equal(t, []string{"double_round_on_rearm_min_1s"}, timerFunc(core.NewProposerDuty(gloasSlot)).Extensions())

	// Other duties are unaffected by gloas.
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAggregatorDuty(gloasSlot)).Type())
	require.Equal(t, []string{"double_total_on_rearm"}, timerFunc(core.NewAggregatorDuty(gloasSlot)).Extensions())

	// The gloas attester and proposer timers don't depend on the legacy timer features: the gloas
	// proposer timer is selected by the cluster agreement, not the local linear feature.
	featureset.DisableForT(t, featureset.EagerDoubleLinear)
	featureset.EnableForT(t, featureset.Linear)

	timerFunc = timer.GetRoundTimerFunc(time.Time{}, 0, slotsPerEpoch, zeroOffsetFunc, forkSchedule, proposerTimerFunc)
	require.Equal(t, timer.TimerIncreasing, timerFunc(core.NewAttesterDuty(gloasSlot-1)).Type())
	require.Equal(t, timer.TimerEagerAheadSplit, timerFunc(core.NewAttesterDuty(gloasSlot)).Type())
	require.Equal(t, timer.TimerLinear, timerFunc(core.NewProposerDuty(gloasSlot-1)).Type())
	require.Equal(t, []string{"reset_on_rearm", "proposal_timeout"}, timerFunc(core.NewProposerDuty(gloasSlot-1)).Extensions())
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewProposerDuty(gloasSlot)).Type())

	// The cluster agreeing on the linear proposer timer selects it, with its agreed inputs, from gloas only.
	proposerTimer = "linear/1.5s/300ms"

	require.Equal(t, []string{"reset_on_rearm", "proposal_timeout"}, timerFunc(core.NewProposerDuty(gloasSlot-1)).Extensions())
	require.Equal(t, timer.TimerLinear, timerFunc(core.NewProposerDuty(gloasSlot)).Type())
	require.Equal(t, []string{"double_round_on_rearm_min_1s"}, timerFunc(core.NewProposerDuty(gloasSlot)).Extensions())

	featureset.DisableForT(t, featureset.Linear)
	require.Equal(t, timer.TimerLinear, timerFunc(core.NewProposerDuty(gloasSlot)).Type())
}
