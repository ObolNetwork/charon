// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package timer

import (
	"slices"
	"time"

	"github.com/obolnetwork/charon/core"
)

// proposalRoundExtra is how much the proposal timeout extends the first round of proposer duties,
// giving extra time for fetching the block proposal.
const proposalRoundExtra = 500 * time.Millisecond

// extension acts on top of a timer, leaving its round durations unchanged, and can be plugged into
// any timer: timers declare their own extensions, and the selection adds extensions for duties. An
// extension acts when a round is armed (onArm), when a round is armed again (onRearm), or
// both.
type extension interface {
	// name returns the name of the extension, identifying it, so unique among extensions.
	name() string
	// appliesForDuty returns true if the extension applies to the duty.
	appliesForDuty(duty core.Duty) bool
	// onArm returns the total time the extension adds to the durations of the rounds up to and
	// including the round, when armed. Being cumulative keeps computing a round's end constant time.
	onArm(round int64) time.Duration
	// onRearm returns the new deadline of the round armed again, given
	// the round's duration and end including extras and its deadline when armed, or false if the
	// extension doesn't act upon it.
	onRearm(duration, end time.Duration, deadline, now time.Time) (time.Time, bool)
}

// noopExtension provides the default extension behaviour: applying to every duty without acting.
// Extensions embed it, overriding the methods they act through.
type noopExtension struct{}

func (noopExtension) appliesForDuty(core.Duty) bool { return true }

func (noopExtension) onArm(int64) time.Duration { return 0 }

func (noopExtension) onRearm(time.Duration, time.Duration, time.Time, time.Time) (time.Time, bool) {
	return time.Time{}, false
}

// resetOnRearm resets the round's timer when the round is armed again: the round then lasts its
// full duration again.
type resetOnRearm struct{ noopExtension }

func (resetOnRearm) name() string { return "reset_on_rearm" }

func (resetOnRearm) onRearm(duration, _ time.Duration, _, now time.Time) (time.Time, bool) {
	return now.Add(duration), true
}

// doubleOnRearm extends the round when it is armed again, from its deadline by the round's end,
// doubling the time since the start of the first round. Extending from the deadline, rather than
// resetting the round's timer, keeps round end times aligned across peers: QBFT arms a round again
// upon a justified pre-prepare, so resetting has no effect on the leader, who resets at the start of
// the round, while it has a large effect on the other peers, who reset when they receive the
// justified pre-prepare.
type doubleOnRearm struct{ noopExtension }

func (doubleOnRearm) name() string { return "double_on_rearm" }

func (doubleOnRearm) onRearm(_, end time.Duration, deadline, _ time.Time) (time.Time, bool) {
	return deadline.Add(end), true
}

// proposalTimeout adds 500ms to the first round of proposer duties.
type proposalTimeout struct{ noopExtension }

func (proposalTimeout) name() string { return "proposal_timeout" }

func (proposalTimeout) appliesForDuty(duty core.Duty) bool {
	return duty.Type == core.DutyProposer
}

func (proposalTimeout) onArm(round int64) time.Duration {
	if round < 1 {
		return 0
	}

	return proposalRoundExtra
}

// withExtensions returns the timer selected for the duty, with its own extensions followed by the
// provided ones, keeping those applying to the duty. Each extension is kept once, at its first
// occurrence, so it never acts twice.
func withExtensions(duty core.Duty, def timerDef, extensions ...extension) timerDef {
	var (
		applied []extension
		names   = make(map[string]bool)
	)

	for _, ext := range slices.Concat(def.extensions, extensions) {
		if names[ext.name()] || !ext.appliesForDuty(duty) {
			continue
		}

		names[ext.name()] = true
		applied = append(applied, ext)
	}

	def.extensions = applied

	return def
}
