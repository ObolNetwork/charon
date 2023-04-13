// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIncreasingRoundTimer(t *testing.T) {
	tests := []struct {
		name  string
		round int64
		want  time.Duration
	}{
		{
			name:  "round 0",
			round: 0,
			want:  750 * time.Millisecond,
		},
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

			timer.Proposed(tt.round) // This should be a noop.

			// Advance the fake clock
			fakeClock.Advance(tt.want)

			// Check if the timer fires
			select {
			case <-timerC:
			default:
				require.Fail(t, "Timer(round %d) did not fire, want %v", tt.round, tt.want)
			}

			// Stop the timer
			stop()
		})
	}
}

func TestDoubleTimeoutRoundTimer(t *testing.T) {
	tests := []struct {
		name         string
		round        int64
		prevProposed bool
		want         time.Duration
	}{
		{
			name:  "round 1",
			round: 1,
			want:  1 * time.Second,
		},
		{
			name:         "round 2 - proposed",
			round:        2,
			prevProposed: true,
			want:         2 * time.Second,
		},
		{
			name:  "round 3 - not proposed",
			round: 3,
			want:  2 * time.Second,
		},
		{
			name:         "round 4 - proposed",
			round:        4,
			prevProposed: true,
			want:         4 * time.Second,
		},
	}

	fakeClock := clockwork.NewFakeClock()
	timer := newDoubleTimeoutRoundTimer()
	timer.clock = fakeClock

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.prevProposed {
				timer.Proposed(tt.round - 1)
			}

			timerC, stop := timer.Timer(tt.round)

			// Advance the fake clock
			fakeClock.Advance(tt.want)

			// Check if the timer fires
			select {
			case <-timerC:
			default:
				assert.Fail(t, "Timer(round %d) did not fire, want %v", tt.round, tt.want)
			}

			// Stop the timer
			stop()
		})
	}
}
