// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package timer_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus/timer"
)

// zeroOffsetFunc is a slot offset function that starts all duties at the start of the slot.
var zeroOffsetFunc core.SlotOffsetFunc = func(core.Duty) time.Duration { return 0 }

func TestGetTimerFunc(t *testing.T) {
	// Use zero values for tests to use default clock.Now() behavior
	genesisTime := time.Time{}
	slotDuration := time.Duration(0)

	timerFunc := timer.GetRoundTimerFunc(genesisTime, slotDuration, zeroOffsetFunc)
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(0)).Type())
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(1)).Type())
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(2)).Type())

	featureset.DisableForT(t, featureset.EagerDoubleLinear)

	timerFunc = timer.GetRoundTimerFunc(genesisTime, slotDuration, zeroOffsetFunc)
	require.Equal(t, timer.TimerIncreasing, timerFunc(core.NewAttesterDuty(0)).Type())
	require.Equal(t, timer.TimerIncreasing, timerFunc(core.NewAttesterDuty(1)).Type())
	require.Equal(t, timer.TimerIncreasing, timerFunc(core.NewAttesterDuty(2)).Type())

	featureset.EnableForT(t, featureset.Linear)

	timerFunc = timer.GetRoundTimerFunc(genesisTime, slotDuration, zeroOffsetFunc)
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
