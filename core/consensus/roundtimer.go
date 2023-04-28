// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"strings"
	"sync"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/core"
)

const (
	incRoundStart    = time.Millisecond * 750
	incRoundIncrease = time.Millisecond * 250
)

// timerFunc is a function that returns a round timer.
type timerFunc func(core.Duty) roundTimer

// getTimerFunc returns a timer function based on the enabled features.
func getTimerFunc() timerFunc {
	if featureset.Enabled(featureset.QBFTTimersABTest) {
		return func(duty core.Duty) roundTimer {
			switch (duty.Slot + int64(duty.Type)) % 3 {
			case 0:
				return newIncreasingRoundTimer()
			case 1:
				return newDoubleLeadRoundTimer()
			case 2:
				return newExponentialRoundTimer()
			default:
				panic("unreachable")
			}
		}
	}

	// Default to increasing round timer.
	return func(core.Duty) roundTimer {
		return newIncreasingRoundTimer()
	}
}

// timerType is the type of round timer.
type timerType string

// Eager returns true if the timer type requires an eager start (before proposal values are present).
func (t timerType) Eager() bool {
	return strings.Contains(string(t), "eager")
}

const (
	timerIncreasing  timerType = "inc"
	timerDoubleLead  timerType = "double"
	timerExponential timerType = "exp"
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
	// Type returns the type of the round timerType.
	Type() timerType
}

// newTimeoutRoundTimer returns a new increasing round timerType.
func newIncreasingRoundTimer() *increasingRoundTimer {
	return &increasingRoundTimer{
		clock: clockwork.NewRealClock(),
	}
}

// increasingRoundTimer implements a linear increasing round timerType.
type increasingRoundTimer struct {
	clock clockwork.Clock
}

func (increasingRoundTimer) Type() timerType {
	return timerIncreasing
}

func (t increasingRoundTimer) Timer(round int64) (<-chan time.Time, func()) {
	timer := t.clock.NewTimer(increasingRoundTimeout(round))
	return timer.Chan(), func() { timer.Stop() }
}

// newDoubleLeadRoundTimer returns a new double lead round timerType.
func newDoubleLeadRoundTimer() *doubleLeadRoundTimer {
	return &doubleLeadRoundTimer{
		clock:          clockwork.NewRealClock(),
		firstDeadlines: make(map[int64]time.Time),
	}
}

// doubleLeadRoundTimer implements a round timerType that double the round duration when a leader is active.
// Instead of resetting the round timerType on justified pre-prepare, rather double the timeout.
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

func (*doubleLeadRoundTimer) Type() timerType {
	return timerDoubleLead
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

// newExponentialRoundTimer returns a new exponential round timerType.
func newExponentialRoundTimer() *exponentialRoundTimer {
	return &exponentialRoundTimer{
		clock: clockwork.NewRealClock(),
	}
}

// exponentialRoundTimer implements a exponential increasing round timer
// starting at incRoundStart and doubling each subsequent round.
type exponentialRoundTimer struct {
	clock clockwork.Clock
}

func (exponentialRoundTimer) Type() timerType {
	return timerExponential
}

func (t exponentialRoundTimer) Timer(round int64) (<-chan time.Time, func()) {
	duration := incRoundStart // Duration starts at incRoundStart.
	for i := 1; i < int(round); i++ {
		duration *= 2 // Duration doubles each subsequent round.
	}
	timer := t.clock.NewTimer(duration)

	return timer.Chan(), func() { timer.Stop() }
}
