// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"sync"
	"time"

	"github.com/jonboulle/clockwork"
)

const (
	incRoundStart    = time.Millisecond * 750
	incRoundIncrease = time.Millisecond * 250
)

// increasingRoundTimeout returns the duration for a round that starts at incRoundStart in round 1
// and increases by incRoundIncrease for each subsequent round.
func increasingRoundTimeout(round int64) time.Duration {
	return incRoundStart + (time.Duration(round) * incRoundIncrease)
}

// roundTimer provides the duration for each QBFT round.
type roundTimer interface {
	// Timer returns a channel that will be closed when the round expires and a stop function.
	Timer(round int64) (<-chan time.Time, func())
}

// newTimeoutRoundTimer returns a new increasing round timer.
func newIncreasingRoundTimer() *increasingRoundTimer {
	return &increasingRoundTimer{
		clock: clockwork.NewRealClock(),
	}
}

// increasingRoundTimer implements a linear increasing round timer.
// It ignores the Cancel call.
type increasingRoundTimer struct {
	clock clockwork.Clock
}

func (t increasingRoundTimer) Timer(round int64) (<-chan time.Time, func()) {
	timer := t.clock.NewTimer(increasingRoundTimeout(round))
	return timer.Chan(), func() {}
}

// newDoubleLeadRoundTimer returns a new double lead round timer.
func newDoubleLeadRoundTimer() *doubleLeadRoundTimer {
	return &doubleLeadRoundTimer{
		clock:          clockwork.NewRealClock(),
		firstDeadlines: make(map[int64]time.Time),
	}
}

// doubleLeadRoundTimer implements a round timer that double the round duration when a leader is active.
// Instead of resetting the round timer on justified pre-prepare, rather double the timeout.
// This ensures all peers round end-times remain aligned with round start times.
//
// The original solution is to reset the round time on justified pre-prepare, but this causes
// the leader to reset at the start of the round, which has no effect, while others reset when
// they receive the justified pre-prepare, which has a large effect. Leaders have a tendency to
// get out of sync with the rest, since they effectively don't extend their rounds.
//
// It extends increasingRoundTimer otherwise.
type doubleLeadRoundTimer struct {
	clock clockwork.Clock

	mu             sync.Mutex
	firstDeadlines map[int64]time.Time
}

func (t *doubleLeadRoundTimer) Timer(round int64) (<-chan time.Time, func()) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var deadline time.Time
	if first, ok := t.firstDeadlines[round]; ok {
		// Deadline is either double the first timeout
		deadline = first.Add(increasingRoundTimeout(round))
	} else {
		// Or the first timeout
		deadline = t.clock.Now().Add(increasingRoundTimeout(round))
		t.firstDeadlines[round] = deadline
	}

	timer := t.clock.NewTimer(deadline.Sub(t.clock.Now()))

	return timer.Chan(), func() { timer.Stop() }
}
