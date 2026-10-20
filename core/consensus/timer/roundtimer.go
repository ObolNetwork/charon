// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package timer

import (
	"sync"
	"testing"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/core"
)

// RoundTimerFunc is a function that returns a round timer.
type RoundTimerFunc func(core.Duty) RoundTimer

// GetRoundTimerFunc returns a timer function based on the fork schedule and the enabled features.
// Genesis time and slot duration are required to calculate deterministic slot start times, while
// the slot offset function provides the duty's offset into the slot at which consensus starts.
func GetRoundTimerFunc(genesisTime time.Time, slotDuration time.Duration, slotsPerEpoch uint64,
	slotOffsetFunc core.SlotOffsetFunc, forkSchedule func() eth2wrap.ForkForkSchedule,
) RoundTimerFunc {
	timing := slotTiming{
		genesisTime:  genesisTime,
		slotDuration: slotDuration,
		slotOffset:   slotOffsetFunc,
	}

	return func(duty core.Duty) RoundTimer {
		gloas := forkSchedule().Active(eth2wrap.Gloas, eth2p0.Epoch(duty.Slot/slotsPerEpoch))

		return newRoundTimer(duty, selectTimer(duty, gloas), timing, clockwork.NewRealClock())
	}
}

// selectTimer returns the timer for the duty, as selected by the fork, whether gloas is active at the
// duty's slot, and the feature set, with its extensions.
func selectTimer(duty core.Duty, gloas bool) timerDef {
	var def timerDef

	switch {
	case duty.Type == core.DutyAttester && gloas:
		// From gloas, attester duties use the eager ahead split timer regardless of the feature set,
		// since round end times must be identical across the cluster.
		// TODO(post-gloas): make this the default for attester duties without the gloas check, removing
		// the fork schedule from GetRoundTimerFunc.
		def = eagerAheadSplitTimer()
	case duty.Type == core.DutyProposer && featureset.Enabled(featureset.Linear):
		// The linear timer has precedence over the eager double linear timer, but only for proposer duties.
		def = linearTimer()
	case featureset.Enabled(featureset.EagerDoubleLinear):
		def = eagerDLinearTimer()
	default:
		def = incTimer()
	}

	return withExtensions(duty, def, featureExtensions()...)
}

// featureExtensions returns the extensions added to every duty's timer, as enabled by the feature set.
func featureExtensions() []extension {
	var extensions []extension
	if featureset.Enabled(featureset.ProposalTimeout) {
		extensions = append(extensions, proposalTimeout{})
	}

	return extensions
}

// Type is the type of round timer.
type Type string

const (
	TimerIncreasing        Type = "inc"
	TimerEagerDoubleLinear Type = "eager_dlinear"
	TimerLinear            Type = "linear"
	TimerEagerAheadSplit   Type = "eager_ahead_split"
)

// RoundTimer provides the duration for each consensus round.
type RoundTimer interface {
	// Timer returns a channel that will be closed when the round expires and a stop function.
	Timer(round int64) (<-chan time.Time, func())
	// Type returns the type of the round timerType.
	Type() Type
	// Extensions returns the names of the extensions in effect, in the order they act.
	Extensions() []string
}

// NewIncreasingForT returns a new increasing round timer with a custom clock, for testing.
func NewIncreasingForT(_ *testing.T, clock clockwork.Clock) RoundTimer {
	return newRoundTimer(core.Duty{}, withExtensions(core.Duty{}, incTimer()), slotTiming{}, clock)
}

// roundDurations defines the durations of a timer's rounds: the first round, then steps rounds of
// step each, then rounds growing by growth each, for liveness. Rounds start at 1.
type roundDurations struct {
	first  time.Duration
	step   time.Duration
	steps  int64
	growth time.Duration
}

// duration returns the duration of the round.
func (d roundDurations) duration(round int64) time.Duration {
	if round <= 1 {
		return d.first
	}

	tail := round - d.steps - 1
	if tail <= 0 {
		return d.step
	}

	return d.step + time.Duration(tail)*d.growth
}

// end returns the end of the round relative to the start of the first round, i.e. the sum of the
// durations of the rounds up to and including it.
func (d roundDurations) end(round int64) time.Duration {
	if round < 1 {
		return 0
	}

	end := d.first + time.Duration(round-1)*d.step

	tail := round - d.steps - 1
	if tail > 0 {
		end += time.Duration(tail*(tail+1)/2) * d.growth
	}

	return end
}

// anchor defines when a timer's rounds start.
type anchor interface {
	// start returns the start of the duty's round armed at now, given the total duration of the rounds
	// before it.
	start(duty core.Duty, timing slotTiming, now time.Time, priorRoundsDuration time.Duration) time.Time
	// lead returns how long before the duty start the first round starts.
	lead() time.Duration
}

// anchorLocalDutyStart starts the first round when the duty starts on this node, and each later round
// when this node enters it, upon its own timeout, round changes or a reset. Rounds thus drift apart
// across peers, further with each round. Only the legacy timers use it.
type anchorLocalDutyStart struct{}

func (anchorLocalDutyStart) start(_ core.Duty, _ slotTiming, now time.Time, _ time.Duration) time.Time {
	return now
}

func (anchorLocalDutyStart) lead() time.Duration { return 0 }

// anchorDutyStart starts the first round at the duty's start, its offset into the slot, with later
// rounds following on at absolute times, aligned across peers.
type anchorDutyStart struct{}

func (anchorDutyStart) start(duty core.Duty, timing slotTiming, now time.Time, priorRoundsDuration time.Duration) time.Time {
	start := timing.dutyStart(duty)
	if start.IsZero() {
		// Without slot timing (only in tests), the first round starts when armed.
		start = now
	}

	return start.Add(priorRoundsDuration)
}

func (anchorDutyStart) lead() time.Duration { return 0 }

// anchorPreviousInterval starts the first round at the start of the interval preceding the duty's
// own, one interval before the duty start, with later rounds following on at absolute times, aligned
// across peers.
type anchorPreviousInterval struct {
	leadTime time.Duration
}

func (a anchorPreviousInterval) start(duty core.Duty, timing slotTiming, now time.Time, priorRoundsDuration time.Duration) time.Time {
	dutyStart := timing.dutyStart(duty)
	if dutyStart.IsZero() {
		// Without slot timing (only in tests), the first round starts when armed.
		return now.Add(priorRoundsDuration)
	}

	return dutyStart.Add(priorRoundsDuration - a.lead())
}

func (a anchorPreviousInterval) lead() time.Duration { return a.leadTime }

// slotTiming provides the slot start times anchored timers start at.
type slotTiming struct {
	genesisTime  time.Time
	slotDuration time.Duration
	slotOffset   core.SlotOffsetFunc
}

// slotStart returns the start of the duty's slot, or the zero time without slot timing (only in tests).
func (s slotTiming) slotStart(duty core.Duty) time.Time {
	if s.genesisTime.IsZero() || s.slotDuration <= 0 {
		return time.Time{}
	}

	return s.genesisTime.Add(s.slotDuration * time.Duration(duty.Slot))
}

// dutyStart returns the start of the duty's slot plus the duty's offset into the slot, or the zero
// time without slot timing (only in tests).
func (s slotTiming) dutyStart(duty core.Duty) time.Time {
	slotStart := s.slotStart(duty)
	if slotStart.IsZero() {
		return time.Time{}
	}

	return slotStart.Add(s.slotOffset(duty))
}

// newRoundTimer returns a round timer running the timer for the duty.
func newRoundTimer(duty core.Duty, def timerDef, timing slotTiming, clock clockwork.Clock) RoundTimer {
	return &roundTimer{
		clock:     clock,
		duty:      duty,
		def:       def,
		timing:    timing,
		deadlines: make(map[int64]time.Time),
	}
}

// roundTimer runs a timer's rounds.
type roundTimer struct {
	clock  clockwork.Clock
	duty   core.Duty
	def    timerDef
	timing slotTiming

	mu        sync.Mutex
	deadlines map[int64]time.Time // The deadline of each round when armed.
}

func (t *roundTimer) Type() Type {
	return t.def.typ
}

func (t *roundTimer) Extensions() []string {
	var names []string
	for _, ext := range t.def.extensions {
		names = append(names, ext.name())
	}

	return names
}

func (t *roundTimer) Timer(round int64) (<-chan time.Time, func()) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.clock.Now()

	deadline, armed := t.deadlines[round]
	if armed {
		deadline = t.rearmDeadline(round, deadline, now)
	} else {
		deadline = t.deadline(round, now)
		t.deadlines[round] = deadline
	}

	timer := t.clock.NewTimer(deadline.Sub(now))

	return timer.Chan(), func() { timer.Stop() }
}

// rearmDeadline returns the deadline of the round armed again, as defined by the first extension
// acting upon it, or its deadline if none does. In practice, QBFT rearms the current round
// upon a justified pre-prepare for it. Three extensions currently act upon this rearming, declared
// by the timers: resetOnRearm by inc and linear, doubleTotalOnRearm by eager_dlinear, and
// doubleRoundOnRearm by eager_ahead_split.
func (t *roundTimer) rearmDeadline(round int64, currentDeadline, now time.Time) time.Time {
	for _, ext := range t.def.extensions {
		adjustedDeadline, ok := ext.onRearm(t.duration(round), t.end(round), t.def.anchor.lead(), currentDeadline, now)
		if ok {
			return adjustedDeadline
		}
	}

	return currentDeadline
}

// deadline returns the deadline of the round when armed.
func (t *roundTimer) deadline(round int64, now time.Time) time.Time {
	start := t.def.anchor.start(t.duty, t.timing, now, t.end(round-1))

	return start.Add(t.duration(round))
}

// duration returns the duration of the round, including the extras of the extensions, unlike
// roundDurations.duration, which only covers the timer's own round durations.
func (t *roundTimer) duration(round int64) time.Duration {
	duration := t.def.durations.duration(round)
	for _, ext := range t.def.extensions {
		duration += ext.onArm(round)
	}

	return duration
}

// end returns the end of the round relative to the start of the first round, including the extras
// of the extensions for the rounds up to and including it, unlike roundDurations.end.
func (t *roundTimer) end(round int64) time.Duration {
	end := t.def.durations.end(round)
	for _, ext := range t.def.extensions {
		for r := int64(1); r <= round; r++ {
			end += ext.onArm(r)
		}
	}

	return end
}
