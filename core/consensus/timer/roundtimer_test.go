// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package timer_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus/timer"
)

func TestIncreasingRoundTimer(t *testing.T) {
	tests := []struct {
		name  string
		round int64
		want  time.Duration
	}{
		{
			name:  "round 1",
			round: 1,
			want:  1000 * time.Millisecond,
		},
		{
			name:  "round 2",
			round: 2,
			want:  1250 * time.Millisecond,
		},
		{
			name:  "round 10",
			round: 10,
			want:  3250 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		fakeClock := clockwork.NewFakeClock()
		timer := timer.NewIncreasingRoundTimerWithClock(fakeClock)

		t.Run(tt.name, func(t *testing.T) {
			// Start the timerType
			timerC, stop := timer.Timer(tt.round)

			// Advance the fake clock
			fakeClock.Advance(tt.want)

			// Check if the timerType fires
			select {
			case <-timerC:
			default:
				require.Fail(t, "Fail", "Timer(round %d) did not fire, want %v", tt.round, tt.want)
			}

			// Stop the timerType
			stop()
		})
	}
}

func TestDoubleEagerLinearRoundTimer(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()
	timer := timer.NewDoubleEagerLinearRoundTimerWithClock(fakeClock)

	require.True(t, timer.Type().Eager())

	assert := func(t *testing.T, ch <-chan time.Time, d time.Duration, expect bool) {
		t.Helper()

		// Advance the fake clock
		fakeClock.Advance(d)

		// Check if the timerType fired as expected
		select {
		case <-ch:
			if !expect {
				require.Fail(t, "Timer fired", "After %d", d)
			}
		default:
			if expect {
				require.Fail(t, "Timer did not fire", "After %d", d)
			}
		}
	}

	// Get round 1 timerType.
	timerC, stop := timer.Timer(1)
	// Assert it times out after 1000ms
	assert(t, timerC, 1000*time.Millisecond, true)
	stop()

	// Get round 1 timerType again.
	timerC, stop = timer.Timer(1)
	// Assert it times out after 1000ms again
	assert(t, timerC, 1000*time.Millisecond, true)
	stop()

	// Get round 2 timerType.
	timerC, stop = timer.Timer(2)
	// Advance time by 1.5s (0.5s remains).
	assert(t, timerC, 1500*time.Millisecond, false)
	stop()

	// Get round 2 timerType again.
	timerC, stop = timer.Timer(2)
	// Assert it times out after 0.5ms+2s
	assert(t, timerC, 2500*time.Millisecond, true)
	stop()
}

func TestLinearRoundTimer(t *testing.T) {
	tests := []struct {
		name  string
		round int64
		want  time.Duration
	}{
		{
			name:  "round 1",
			round: 1,
			want:  1000 * time.Millisecond,
		},
		{
			name:  "round 2",
			round: 2,
			want:  400 * time.Millisecond,
		},
		{
			name:  "round 3",
			round: 3,
			want:  600 * time.Millisecond,
		},
		{
			name:  "round 4",
			round: 4,
			want:  800 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		fakeClock := clockwork.NewFakeClock()
		timer := timer.NewLinearRoundTimerWithClock(fakeClock)

		t.Run(tt.name, func(t *testing.T) {
			// Start the timerType
			timerC, stop := timer.Timer(tt.round)

			// Advance the fake clock
			fakeClock.Advance(tt.want)

			// Check if the timerType fires
			select {
			case <-timerC:
			default:
				require.Fail(t, "Fail", "Timer(round %d) did not fire, want %v", tt.round, tt.want)
			}

			// Stop the timerType
			stop()
		})
	}
}

func TestGetTimerFunc(t *testing.T) {
	timerFunc := timer.GetRoundTimerFunc()
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(0)).Type())
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(1)).Type())
	require.Equal(t, timer.TimerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(2)).Type())

	featureset.DisableForT(t, featureset.EagerDoubleLinear)

	timerFunc = timer.GetRoundTimerFunc()
	require.Equal(t, timer.TimerIncreasing, timerFunc(core.NewAttesterDuty(0)).Type())
	require.Equal(t, timer.TimerIncreasing, timerFunc(core.NewAttesterDuty(1)).Type())
	require.Equal(t, timer.TimerIncreasing, timerFunc(core.NewAttesterDuty(2)).Type())

	featureset.EnableForT(t, featureset.Linear)

	timerFunc = timer.GetRoundTimerFunc()
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

func TestProposalTimeoutOptimizationIncreasingRoundTimer(t *testing.T) {
	featureset.EnableForT(t, featureset.ProposalTimeout)
	defer featureset.DisableForT(t, featureset.ProposalTimeout)

	fakeClock := clockwork.NewFakeClock()
	duty := core.NewProposerDuty(0)
	timerDutyClock := timer.NewIncreasingRoundTimerWithDutyAndClock(duty, fakeClock)

	// First round for proposer should be 1.5s
	timerC, stop := timerDutyClock.Timer(1)

	fakeClock.Advance(1500 * time.Millisecond)

	select {
	case <-timerC:
	default:
		require.Fail(t, "Timer(round 1, proposer) did not fire at 1.5s")
	}

	stop()

	// Second round should use original logic
	timerC, stop = timerDutyClock.Timer(2)

	fakeClock.Advance(timer.IncRoundStart + 2*timer.IncRoundIncrease)

	select {
	case <-timerC:
	default:
		require.Fail(t, "Timer(round 2, proposer) did not fire at original duration")
	}

	stop()
}

func TestProposalTimeoutOptimizationDoubleEagerLinearRoundTimer(t *testing.T) {
	featureset.EnableForT(t, featureset.ProposalTimeout)
	defer featureset.DisableForT(t, featureset.ProposalTimeout)

	fakeClock := clockwork.NewFakeClock()
	duty := core.NewProposerDuty(0)
	timer := timer.NewDoubleEagerLinearRoundTimerWithDutyAndClock(duty, fakeClock)

	// First round for proposer should be 1.5s
	timerC, stop := timer.Timer(1)

	fakeClock.Advance(1500 * time.Millisecond)

	select {
	case <-timerC:
	default:
		require.Fail(t, "Timer(round 1, proposer) did not fire at 1.5s")
	}

	stop()

	// Second round should use original logic (2s)
	timerC, stop = timer.Timer(2)

	fakeClock.Advance(2 * time.Second)

	select {
	case <-timerC:
	default:
		require.Fail(t, "Timer(round 2, proposer) did not fire at 2s")
	}

	stop()
}

func TestProposalTimeoutOptimizationLinearRoundTimer(t *testing.T) {
	featureset.EnableForT(t, featureset.ProposalTimeout)
	defer featureset.DisableForT(t, featureset.ProposalTimeout)

	fakeClock := clockwork.NewFakeClock()
	duty := core.NewProposerDuty(0)
	timer := timer.NewLinearRoundTimerWithDutyAndClock(duty, fakeClock)

	// First round for proposer should be 1.5s
	timerC, stop := timer.Timer(1)

	fakeClock.Advance(1500 * time.Millisecond)

	select {
	case <-timerC:
	default:
		require.Fail(t, "Timer(round 1, proposer) did not fire at 1.5s")
	}

	stop()

	// Third round should use original logic (600ms)
	timerC, stop = timer.Timer(3)

	fakeClock.Advance(600 * time.Millisecond)

	select {
	case <-timerC:
	default:
		require.Fail(t, "Timer(round 3, proposer) did not fire at 600ms")
	}

	stop()
}
