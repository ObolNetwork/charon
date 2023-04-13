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
// It ignores the proposed call.
type increasingRoundTimer struct {
	clock clockwork.Clock
}

func (t increasingRoundTimer) Timer(round int64) (<-chan time.Time, func()) {
	timer := t.clock.NewTimer(incRoundStart + (time.Duration(round) * incRoundIncrease))
	return timer.Chan(), func() {}
}

// newNoResetRoundTimer returns a new no-reset round timer.
func newNoResetRoundTimer() *noResetRoundTimer {
	return &noResetRoundTimer{
		increasingRoundTimer: newIncreasingRoundTimer(),
		timers:               make(map[int64]<-chan time.Time),
	}
}

// noResetRoundTimer implements a round timer that does not reset active round timers.
// This results in not reset round timers on receive of justified pre-prepare messages for the current round.
// It extends increasingRoundTimer otherwise.
type noResetRoundTimer struct {
	*increasingRoundTimer

	mu     sync.Mutex
	timers map[int64]<-chan time.Time
}

func (t *noResetRoundTimer) Timer(round int64) (<-chan time.Time, func()) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if timer, ok := t.timers[round]; ok {
		return timer, func() {}
	}

	timer, _ := t.increasingRoundTimer.Timer(round)

	t.timers[round] = timer

	return timer, func() {}
}
