// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"math/rand"
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
	linearRoundInc   = time.Second
)

// timerFunc is a function that returns a round timer.
type timerFunc func(core.Duty) roundTimer

// getTimerFunc returns a timer function based on the enabled features.
func getTimerFunc() timerFunc {
	if featureset.Enabled(featureset.QBFTTimersABTest) {
		abTimers := []func() roundTimer{
			newIncreasingRoundTimer,
			newDoubleEagerLinearRoundTimer,
		}

		return func(duty core.Duty) roundTimer {
			random := rand.New(rand.NewSource(int64(uint64(duty.Type) + duty.Slot))) //nolint:gosec // Required for consistent pseudo-randomness.
			return abTimers[random.Intn(len(abTimers))]()
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
	timerIncreasing        timerType = "inc"
	timerEagerDoubleLinear timerType = "eager_dlinear"
)

// increasingRoundTimeout returns the duration for a round that starts at incRoundStart in round 1
// and increases by incRoundIncrease for each subsequent round.
func increasingRoundTimeout(round int64) time.Duration {
	return incRoundStart + (time.Duration(round) * incRoundIncrease)
}

// increasingRoundTimeout returns linearRoundInc*round duration for a round.
func linearRoundTimeout(round int64) time.Duration {
	return time.Duration(round) * linearRoundInc
}

// roundTimer provides the duration for each QBFT round.
type roundTimer interface {
	// Timer returns a channel that will be closed when the round expires and a stop function.
	Timer(round int64) (<-chan time.Time, func())
	// Type returns the type of the round timerType.
	Type() timerType
}

// newTimeoutRoundTimer returns a new increasing round timerType.
func newIncreasingRoundTimer() roundTimer {
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

// doubleEagerLinearRoundTimer returns a new eager double linear round timerType.
func newDoubleEagerLinearRoundTimer() roundTimer {
	return &doubleEagerLinearRoundTimer{
		clock:          clockwork.NewRealClock(),
		firstDeadlines: make(map[int64]time.Time),
	}
}

// doubleEagerLinearRoundTimer implements a round timerType with the following properties:
//
// It doubles the round duration when a leader is active.
// Instead of resetting the round timerType on justified pre-prepare, rather double the timeout.
// This ensures all peers round end-times remain aligned with round start times.
// The original solution is to reset the round time on justified pre-prepare, but this causes
// the leader to reset at the start of the round, which has no effect, while others reset when
// they receive the justified pre-prepare, which has a large effect. Leaders have a tendency to
// get out of sync with the rest, since they effectively don't extend their rounds.
//
// It is eager, meaning it starts at an absolute time before the proposal values are present.
// This aligns the round start times of all peers, which is important for the leader election.
//
// It is linear, meaning the round duration increases linearly with the round number: 1s, 2s, 3s, etc.
type doubleEagerLinearRoundTimer struct {
	clock clockwork.Clock

	mu             sync.Mutex
	firstDeadlines map[int64]time.Time
}

func (*doubleEagerLinearRoundTimer) Type() timerType {
	return timerEagerDoubleLinear
}

func (t *doubleEagerLinearRoundTimer) Timer(round int64) (<-chan time.Time, func()) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var deadline time.Time
	if first, ok := t.firstDeadlines[round]; ok {
		// Deadline is either double the first timeout
		deadline = first.Add(linearRoundTimeout(round))
	} else {
		// Or the first timeout
		deadline = t.clock.Now().Add(linearRoundTimeout(round))
		t.firstDeadlines[round] = deadline
	}

	timer := t.clock.NewTimer(deadline.Sub(t.clock.Now()))

	return timer.Chan(), func() { timer.Stop() }
}
