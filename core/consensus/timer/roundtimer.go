// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package timer

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

// RoundTimerFunc is a function that returns a round timer.
type RoundTimerFunc func(core.Duty) RoundTimer

// GetRoundTimerFunc returns a timer function based on the enabled features.
// Genesis time and slot duration are required to calculate deterministic slot start times.
func GetRoundTimerFunc(genesisTime time.Time, slotDuration time.Duration) RoundTimerFunc {
	if featureset.Enabled(featureset.Linear) {
		return func(duty core.Duty) RoundTimer {
			// Linear timer only affects Proposer duty
			if duty.Type == core.DutyProposer {
				return NewLinearRoundTimerWithDuty(duty)
			} else if featureset.Enabled(featureset.EagerDoubleLinear) {
				return NewDoubleEagerLinearRoundTimerWithDutyAndTiming(duty, genesisTime, slotDuration)
			}

			return NewIncreasingRoundTimerWithDuty(duty)
		}
	}

	if featureset.Enabled(featureset.EagerDoubleLinear) {
		return func(duty core.Duty) RoundTimer {
			return NewDoubleEagerLinearRoundTimerWithDutyAndTiming(duty, genesisTime, slotDuration)
		}
	}

	// Default to increasing round timer.
	return NewIncreasingRoundTimerWithDuty
}

// Type is the type of round timer.
type Type string

// Eager returns true if the timer type requires an eager start (before proposal values are present).
func (t Type) Eager() bool {
	return strings.Contains(string(t), "eager")
}

const (
	TimerIncreasing        Type = "inc"
	TimerEagerDoubleLinear Type = "eager_dlinear"
	TimerLinear            Type = "linear"
)

// increasingRoundTimeout returns the duration for a round that starts at incRoundStart in round 1
// and increases by incRoundIncrease for each subsequent round.
func increasingRoundTimeout(round int64) time.Duration {
	return IncRoundStart + (time.Duration(round) * IncRoundIncrease)
}

// linearRoundTimeout returns linearRoundInc*round duration for a round.
func linearRoundTimeout(round int64) time.Duration {
	return time.Duration(round) * LinearRoundInc
}

// RoundTimer provides the duration for each consensus round.
type RoundTimer interface {
	// Timer returns a channel that will be closed when the round expires and a stop function.
	Timer(round int64) (<-chan time.Time, func())
	// Type returns the type of the round timerType.
	Type() Type
}

// proposalTimeoutOptimization returns true if ProposalTimeout feature is enabled, the duty is proposer and
// we are in the first round.
func proposalTimeoutOptimization(duty core.Duty, round int64) bool {
	return featureset.Enabled(featureset.ProposalTimeout) && duty.Type == core.DutyProposer && round == 1
}

// getDutyStartDelayWithDuration returns the delay from slot start to when a duty is scheduled to begin,
// given the slot duration. This matches the scheduler's slot offsets to ensure timers align with when
// consensus actually starts.
func getDutyStartDelayWithDuration(dutyType core.DutyType, slotDuration time.Duration) time.Duration {
	switch dutyType {
	case core.DutyAttester:
		return slotDuration / 3
	case core.DutyAggregator, core.DutySyncContribution:
		return (2 * slotDuration) / 3
	default:
		return 0
	}
}

// NewIncreasingRoundTimer returns a new increasing round timer type.
func NewIncreasingRoundTimer() RoundTimer {
	return NewIncreasingRoundTimerWithClock(clockwork.NewRealClock())
}

// NewIncreasingRoundTimerWithClock returns a new increasing round timer type with a custom clock.
func NewIncreasingRoundTimerWithClock(clock clockwork.Clock) RoundTimer {
	return &increasingRoundTimer{
		clock: clock,
	}
}

// NewIncreasingRoundTimerWithDuty returns a new eager double linear round timer type for a specific duty.
func NewIncreasingRoundTimerWithDuty(duty core.Duty) RoundTimer {
	return &increasingRoundTimer{
		clock: clockwork.NewRealClock(),
		duty:  duty,
	}
}

// NewIncreasingRoundTimerWithDutyAndClock returns a new eager double linear round timer type for a specific duty and custom clock.
func NewIncreasingRoundTimerWithDutyAndClock(duty core.Duty, clock clockwork.Clock) RoundTimer {
	return &increasingRoundTimer{
		clock: clock,
		duty:  duty,
	}
}

// increasingRoundTimer implements a linear increasing round timerType.
type increasingRoundTimer struct {
	clock clockwork.Clock
	duty  core.Duty
}

func (increasingRoundTimer) Type() Type {
	return TimerIncreasing
}

func (t increasingRoundTimer) Timer(round int64) (<-chan time.Time, func()) {
	timeout := increasingRoundTimeout(round)
	if proposalTimeoutOptimization(t.duty, round) {
		timeout = 1500 * time.Millisecond
	}

	timer := t.clock.NewTimer(timeout)

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

// NewDoubleEagerLinearRoundTimerWithDuty returns a new eager double linear round timer type for a specific duty.
func NewDoubleEagerLinearRoundTimerWithDuty(duty core.Duty) RoundTimer {
	return &doubleEagerLinearRoundTimer{
		clock:          clockwork.NewRealClock(),
		duty:           duty,
		firstDeadlines: make(map[int64]time.Time),
	}
}

// NewDoubleEagerLinearRoundTimerWithDutyAndClock returns a new eager double linear round timer type for a specific duty and custom clock.
func NewDoubleEagerLinearRoundTimerWithDutyAndClock(duty core.Duty, clock clockwork.Clock) RoundTimer {
	return &doubleEagerLinearRoundTimer{
		clock:          clock,
		duty:           duty,
		firstDeadlines: make(map[int64]time.Time),
	}
}

// NewDoubleEagerLinearRoundTimerWithDutyAndTiming returns a new eager double linear round timer type for a specific duty with genesis time and slot duration.
// This ensures deterministic behavior across all nodes by using slot start time as the reference.
func NewDoubleEagerLinearRoundTimerWithDutyAndTiming(duty core.Duty, genesisTime time.Time, slotDuration time.Duration) RoundTimer {
	return &doubleEagerLinearRoundTimer{
		clock:          clockwork.NewRealClock(),
		duty:           duty,
		genesisTime:    genesisTime,
		slotDuration:   slotDuration,
		firstDeadlines: make(map[int64]time.Time),
	}
}

// NewDoubleEagerLinearRoundTimerWithDutyTimingAndClock returns a new eager double linear round timer type for a specific duty, genesis time, slot duration, and custom clock.
// This is primarily used for testing with fake clocks.
func NewDoubleEagerLinearRoundTimerWithDutyTimingAndClock(duty core.Duty, genesisTime time.Time, slotDuration time.Duration, clock clockwork.Clock) RoundTimer {
	return &doubleEagerLinearRoundTimer{
		clock:          clock,
		duty:           duty,
		genesisTime:    genesisTime,
		slotDuration:   slotDuration,
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
	clock        clockwork.Clock
	duty         core.Duty
	genesisTime  time.Time
	slotDuration time.Duration

	mu             sync.Mutex
	firstDeadlines map[int64]time.Time
}

func (*doubleEagerLinearRoundTimer) Type() Type {
	return TimerEagerDoubleLinear
}

func (t *doubleEagerLinearRoundTimer) Timer(round int64) (<-chan time.Time, func()) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var timeout time.Duration
	if proposalTimeoutOptimization(t.duty, round) {
		timeout = 1500 * time.Millisecond
	} else {
		timeout = linearRoundTimeout(round)
	}

	var deadline time.Time
	if first, ok := t.firstDeadlines[round]; ok {
		// Deadline is either double the first timeout
		deadline = first.Add(timeout)
	} else {
		// Calculate the first deadline.
		// If genesisTime and slotDuration are set, use slot start time for determinism.
		// Otherwise, fall back to clock.Now().
		if !t.genesisTime.IsZero() && t.slotDuration > 0 {
			// Calculate slot start time deterministically from duty slot number.
			slotStart := t.genesisTime.Add(t.slotDuration * time.Duration(t.duty.Slot))

			// Add duty-specific delay to account for when the duty is scheduled to start.
			dutyDelay := getDutyStartDelayWithDuration(t.duty.Type, t.slotDuration)
			dutyStart := slotStart.Add(dutyDelay)

			// Deadline is duty start time plus the round timeout
			deadline = dutyStart.Add(timeout)
		} else {
			deadline = t.clock.Now().Add(timeout)
		}
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
	duty  core.Duty
}

func (*linearRoundTimer) Type() Type {
	return TimerLinear
}

func (t *linearRoundTimer) Timer(round int64) (<-chan time.Time, func()) {
	var timeout time.Duration
	if proposalTimeoutOptimization(t.duty, round) {
		timeout = 1500 * time.Millisecond
	} else if round == 1 {
		// First round has 1 second
		timeout = time.Second
	} else {
		// Subsequent rounds have linearly more time starting at 400 milliseconds
		timeout = time.Duration(200*(round-1) + 200)
	}

	timer := t.clock.NewTimer(timeout)

	return timer.Chan(), func() { timer.Stop() }
}

// NewLinearRoundTimer returns a new linear round timer type.
func NewLinearRoundTimer() RoundTimer {
	return NewLinearRoundTimerWithClock(clockwork.NewRealClock())
}

// NewLinearRoundTimerWithClock returns a new linear round timer type with a custom clock.
func NewLinearRoundTimerWithClock(clock clockwork.Clock) RoundTimer {
	return &linearRoundTimer{
		clock: clock,
	}
}

// NewLinearRoundTimerWithDuty returns a new linear round timer type for a specific duty.
func NewLinearRoundTimerWithDuty(duty core.Duty) RoundTimer {
	return &linearRoundTimer{
		clock: clockwork.NewRealClock(),
		duty:  duty,
	}
}

// NewLinearRoundTimerWithDutyAndClock returns a new linear round timer type for a specific duty and custom clock.
func NewLinearRoundTimerWithDutyAndClock(duty core.Duty, clock clockwork.Clock) RoundTimer {
	return &linearRoundTimer{
		clock: clock,
		duty:  duty,
	}
}
