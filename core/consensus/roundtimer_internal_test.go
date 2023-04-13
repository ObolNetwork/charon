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

func TestDoubleTimeoutRoundTimer(t *testing.T) {
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
			name:  "round 1 again",
			round: 1,
			want:  0 * time.Millisecond,
		},
		{
			name:  "round 2",
			round: 2,
			want:  1250 * time.Millisecond,
		},
		{
			name:  "round 2 again",
			round: 2,
			want:  0 * time.Millisecond,
		},
		{
			name:  "round 3",
			round: 3,
			want:  1500 * time.Millisecond,
		},
	}

	fakeClock := clockwork.NewFakeClock()
	timer := newNoResetRoundTimer()
	timer.clock = fakeClock

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timerC, stop := timer.Timer(tt.round)

			// Advance the fake clock
			fakeClock.Advance(tt.want)

			// Check if the timer fires or will never fire
			select {
			case <-timerC:
				if tt.want == 0 {
					require.Fail(t, "Fail", "Timer(round %d) fired, want never", tt.round)
				}
			default:
				if tt.want != 0 {
					require.Fail(t, "Fail", "Timer(round %d) did not fire, want %v", tt.round, tt.want)
				}
			}

			// Stop the timer
			stop()
		})
	}
}
