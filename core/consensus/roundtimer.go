// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"sync"
	"time"

	"github.com/jonboulle/clockwork"
)

const (
	timeoutRoundStart = time.Second
	incRoundStart     = time.Millisecond * 750
	incRoundIncrease  = time.Millisecond * 250
)

// roundTimer provides the duration for each QBFT round.
type roundTimer interface {
	// Timer returns a channel that will be closed when the round expires and a stop function.
	Timer(round int64) (<-chan time.Time, func())

	// Proposed must be called when the leader of a round successfully proposed (pre-prepare).
	Proposed(round int64)
}

// newTimeoutRoundTimer returns a new increasing round timer.
func newIncreasingRoundTimer() *increasingRoundTimer {
	return &increasingRoundTimer{
		clock: clockwork.NewRealClock(),
	}
}

// increasingRoundTimer implements a 750ms+(round*250ms) increasing round timer.
// It ignores the proposed call.
type increasingRoundTimer struct {
	clock clockwork.Clock
}

func (t increasingRoundTimer) Timer(round int64) (<-chan time.Time, func()) {
	timer := t.clock.NewTimer(incRoundStart + (time.Duration(round) * incRoundIncrease))
	return timer.Chan(), func() { timer.Stop() }
}

func (increasingRoundTimer) Proposed(int64) {}

// newDoubleTimeoutRoundTimer returns a new double timeout round timer.
func newDoubleTimeoutRoundTimer() *doubleTimeoutRoundTimer {
	return &doubleTimeoutRoundTimer{
		clock:          clockwork.NewRealClock(),
		proposedRounds: make(map[int64]bool),
		roundTimeouts:  make(map[int64]time.Duration),
	}
}

// doubleTimeoutRoundTimer implements a round timer that doubles the
// round timeout if the previous round was proposed but still timed out.
// It uses the same timeout as the previous round if the
// previous round was not proposed (so the leader is down).
type doubleTimeoutRoundTimer struct {
	clock          clockwork.Clock
	mu             sync.Mutex
	proposedRounds map[int64]bool
	roundTimeouts  map[int64]time.Duration
}

func (t *doubleTimeoutRoundTimer) Timer(round int64) (<-chan time.Time, func()) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// newTimer returns the timer for this round (once calculated).
	newTimer := func() (<-chan time.Time, func()) {
		timer := t.clock.NewTimer(t.roundTimeouts[round])

		return timer.Chan(), func() { timer.Stop() }
	}

	// Start with a 1s timeout.
	if round == 1 {
		t.roundTimeouts[round] = timeoutRoundStart

		return newTimer()
	}

	// Double the timeout if the previous round was proposed (so we need more time to decide)
	if t.proposedRounds[round-1] {
		t.roundTimeouts[round] = t.roundTimeouts[round-1] * 2
	} else { // Otherwise, use the same timeout as the previous round (leader is down).
		t.roundTimeouts[round] = t.roundTimeouts[round-1]
	}

	return newTimer()
}

func (t *doubleTimeoutRoundTimer) Proposed(round int64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.proposedRounds[round] = true
}
