// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package timer

import "time"

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
		extensions: []extension{doubleOnRearm{}},
	}
}
