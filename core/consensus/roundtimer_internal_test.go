// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
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
		timer := newIncreasingRoundTimer()
		timer.clock = fakeClock

		t.Run(tt.name, func(t *testing.T) {
			// Start the timer
			timerC, stop := timer.Timer(tt.round)

			// Advance the fake clock
			fakeClock.Advance(tt.want)

			// Check if the timer fires
			select {
			case <-timerC:
			default:
				require.Fail(t, "Fail", "Timer(round %d) did not fire, want %v", tt.round, tt.want)
			}

			// Stop the timer
			stop()
		})
	}
}

func TestDoubleLeadRoundTimer(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()
	timer := newDoubleLeadRoundTimer()
	timer.clock = fakeClock

	assert := func(t *testing.T, ch <-chan time.Time, d time.Duration, expect bool) {
		t.Helper()

		// Advance the fake clock
		fakeClock.Advance(d)

		// Check if the timer fired as expected
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

	// Get round 1 timer.
	timerC, stop := timer.Timer(1)
	// Assert it times out after 1000ms
	assert(t, timerC, 1000*time.Millisecond, true)
	stop()

	// Get round 1 timer again.
	timerC, stop = timer.Timer(1)
	// Assert it times out after 1000ms again
	assert(t, timerC, 1000*time.Millisecond, true)
	stop()

	// Get round 2 timer.
	timerC, stop = timer.Timer(2)
	// Advance time by 250ms (1s remains).
	assert(t, timerC, 250*time.Millisecond, false)
	stop()

	// Get round 2 timer again.
	timerC, stop = timer.Timer(2)
	// Assert it times out after 1s+1250ms
	assert(t, timerC, time.Second+1250*time.Millisecond, true)
	stop()
}
