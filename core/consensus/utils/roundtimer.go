// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package utils

import (
	"strings"
	"sync"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/core"
)

const (
	IncRoundStart    = time.Millisecond * 750
	IncRoundIncrease = time.Millisecond * 250
	LinearRoundInc   = time.Second
)

// TimerFunc is a function that returns a round timer.
type TimerFunc func(core.Duty) RoundTimer

// GetTimerFunc returns a timer function based on the enabled features.
func GetTimerFunc() TimerFunc {
	if featureset.Enabled(featureset.Linear) {
		return func(core.Duty) RoundTimer {
			return NewLinearRoundTimer()
		}
	}

	if featureset.Enabled(featureset.EagerDoubleLinear) {
		return func(core.Duty) RoundTimer {
			return NewDoubleEagerLinearRoundTimer()
		}
	}

	// Default to increasing round timer.
	return func(core.Duty) RoundTimer {
		return NewIncreasingRoundTimer()
	}
}

// TimerType is the type of round timer.
type TimerType string

// Eager returns true if the timer type requires an eager start (before proposal values are present).
func (t TimerType) Eager() bool {
	return strings.Contains(string(t), "eager")
}

const (
	TimerIncreasing        TimerType = "inc"
	TimerEagerDoubleLinear TimerType = "eager_dlinear"
	TimerLinear            TimerType = "linear"
)

// increasingRoundTimeout returns the duration for a round that starts at incRoundStart in round 1
// and increases by incRoundIncrease for each subsequent round.
func increasingRoundTimeout(round int64) time.Duration {
	return IncRoundStart + (time.Duration(round) * IncRoundIncrease)
}

// increasingRoundTimeout returns linearRoundInc*round duration for a round.
func linearRoundTimeout(round int64) time.Duration {
	return time.Duration(round) * LinearRoundInc
}

// RoundTimer provides the duration for each consensus round.
type RoundTimer interface {
	// Timer returns a channel that will be closed when the round expires and a stop function.
	Timer(round int64) (<-chan time.Time, func())
	// Type returns the type of the round timerType.
	Type() TimerType
}

// NewTimeoutRoundTimer returns a new increasing round timer type.
func NewIncreasingRoundTimer() RoundTimer {
	return NewIncreasingRoundTimerWithClock(clockwork.NewRealClock())
}

// NewIncreasingRoundTimerWithClock returns a new increasing round timer type with a custom clock.
func NewIncreasingRoundTimerWithClock(clock clockwork.Clock) RoundTimer {
	return &increasingRoundTimer{
		clock: clock,
	}
}

// increasingRoundTimer implements a linear increasing round timerType.
type increasingRoundTimer struct {
	clock clockwork.Clock
}

func (increasingRoundTimer) Type() TimerType {
	return TimerIncreasing
}

func (t increasingRoundTimer) Timer(round int64) (<-chan time.Time, func()) {
	timer := t.clock.NewTimer(increasingRoundTimeout(round))
	return timer.Chan(), func() { timer.Stop() }
}

// NewDoubleEagerLinearRoundTimer returns a new eager double linear round timer type.
func NewDoubleEagerLinearRoundTimer() RoundTimer {
	return NewDoubleEagerLinearRoundTimerWithClock(clockwork.NewRealClock())
}

// NewDoubleEagerLinearRoundTimerWithClock returns a new eager double linear round timer type with a custom clock.
func NewDoubleEagerLinearRoundTimerWithClock(clock clockwork.Clock) RoundTimer {
	return &doubleEagerLinearRoundTimer{
		clock:          clock,
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

func (*doubleEagerLinearRoundTimer) Type() TimerType {
	return TimerEagerDoubleLinear
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

// linearRoundTimer implements a round timerType with the following properties:
//
// The first round has one second to complete consensus
// If this round fails then other peers already had time to fetch proposal and therefore
// won't need as much time to reach a consensus. Therefore start timeout with lower value
// which will increase linearly
type linearRoundTimer struct {
	clock clockwork.Clock
}

func (*linearRoundTimer) Type() TimerType {
	return TimerLinear
}

func (t *linearRoundTimer) Timer(round int64) (<-chan time.Time, func()) {
	var timer clockwork.Timer
	if round == 1 {
		// First round has 1 second
		timer = t.clock.NewTimer(time.Second)
	} else {
		// Subsequent rounds have linearly more time starting at 200 milliseconds
		timer = t.clock.NewTimer(time.Duration(200*(round-1) + 200))
	}

	return timer.Chan(), func() { timer.Stop() }
}

// NewLinearRoundTimer returns a new linear round timer type.
func NewLinearRoundTimer() RoundTimer {
	return NewLinearRoundTimerWithClock(clockwork.NewRealClock())
}

func NewLinearRoundTimerWithClock(clock clockwork.Clock) RoundTimer {
	return &linearRoundTimer{
		clock: clock,
	}
}
