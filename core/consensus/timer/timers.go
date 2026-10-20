// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package timer

import "time"

const (
	// eagerAheadSplitInterval is the length of an interval, the timeframe of a duty in the slot: from
	// the gloas fork a 12s slot has four 3s intervals.
	eagerAheadSplitInterval = 3 * time.Second
	// eagerAheadSplitAttempts is the number of attempts the duty's own interval is split into.
	eagerAheadSplitAttempts = 3
)

const (
	// incRoundStart is the base duration of the increasing timer's rounds, which last
	// incRoundStart + round*incRoundIncrease.
	incRoundStart    = 750 * time.Millisecond
	incRoundIncrease = 250 * time.Millisecond
)

// timerDef defines a timer: its round durations, the start of its first round and its extensions.
type timerDef struct {
	typ        Type
	durations  roundDurations
	anchor     anchor
	extensions []extension
}

// Timers are named configurations of round timing: their round durations, the start of their first
// round and their extensions, such as how a round is extended when armed again.

// incTimer rounds increase linearly from 1s by 250ms each: 1s, 1.25s, 1.5s, etc.
// Rounds start when armed and reset when armed again.
func incTimer() timerDef {
	return timerDef{
		typ: TimerIncreasing,
		durations: roundDurations{
			first:  incRoundStart + incRoundIncrease,
			step:   incRoundStart + incRoundIncrease,
			growth: incRoundIncrease,
		},
		anchor:     anchorLocalDutyStart{},
		extensions: []extension{resetOnRearm{}},
	}
}

// linearTimer has a 1s first round, since all peers fetch their value at its start. Peers already
// have their value in later rounds, which start shorter and grow linearly: 400ms, 600ms, etc.,
// skipping underperforming leaders quicker. Rounds start when armed and reset when armed again.
func linearTimer() timerDef {
	return timerDef{
		typ: TimerLinear,
		durations: roundDurations{
			first:  time.Second,
			step:   200 * time.Millisecond,
			growth: 200 * time.Millisecond,
		},
		anchor:     anchorLocalDutyStart{},
		extensions: []extension{resetOnRearm{}},
	}
}

// eagerDLinearTimer rounds last 1s each, starting at the duty's offset into the slot, before values
// are present. This aligns the round start times of all peers, which is important for the leader
// election. Arming a round again extends it by its end, doubling it.
func eagerDLinearTimer() timerDef {
	return timerDef{
		typ: TimerEagerDoubleLinear,
		durations: roundDurations{
			first: time.Second,
			step:  time.Second,
		},
		anchor:     anchorDutyStart{},
		extensions: []extension{doubleTotalOnRearm{}},
	}
}

// eagerAheadSplitTimer starts its rounds one interval ahead of the duty's own interval, at the start
// of the previous interval, and splits the duty's own interval into equal attempts. With 3s intervals
// and 3 attempts, rounds last 4s, 1s, 1s, 2s, 3s, etc., starting at absolute times aligned across
// peers. Arming a round again extends it by its duration after the duty start, at least 1s.
func eagerAheadSplitTimer() timerDef {
	return timerDef{
		typ:        TimerEagerAheadSplit,
		durations:  aheadSplit(eagerAheadSplitInterval, eagerAheadSplitAttempts),
		anchor:     anchorPreviousInterval{leadTime: eagerAheadSplitInterval},
		extensions: []extension{doubleRoundOnRearm{minimum: time.Second}},
	}
}

// aheadSplit returns round durations starting one interval ahead of the duty's own interval and
// splitting the duty's own interval into equal attempts: the first round spans the previous interval
// plus one attempt, the next rounds one attempt each, and rounds past the attempts grow by a further
// second.
func aheadSplit(interval time.Duration, attempts int64) roundDurations {
	attempt := interval / time.Duration(attempts)

	return roundDurations{
		first:  interval + attempt,
		step:   attempt,
		steps:  attempts - 1,
		growth: time.Second,
	}
}
