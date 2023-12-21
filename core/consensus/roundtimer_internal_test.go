// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/core"
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
		timer := newIncreasingRoundTimer().(*increasingRoundTimer)
		timer.clock = fakeClock

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
	timer := newDoubleEagerLinearRoundTimer().(*doubleEagerLinearRoundTimer)
	timer.clock = fakeClock

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

func TestGetTimerFunc(t *testing.T) {
	timerFunc := getTimerFunc()
	require.Equal(t, timerIncreasing, timerFunc(core.NewAttesterDuty(0)).Type())
	require.Equal(t, timerIncreasing, timerFunc(core.NewAttesterDuty(1)).Type())
	require.Equal(t, timerIncreasing, timerFunc(core.NewAttesterDuty(2)).Type())

	featureset.EnableForT(t, featureset.EagerDoubleLinear)

	timerFunc = getTimerFunc()
	require.Equal(t, timerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(0)).Type())
	require.Equal(t, timerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(1)).Type())
	require.Equal(t, timerEagerDoubleLinear, timerFunc(core.NewAttesterDuty(2)).Type())
}
