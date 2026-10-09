// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package timer

import (
	"fmt"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

// TestTimerDeadlines records the deadlines of every timer, for attester and proposer duties, with and
// without the proposal timeout, so that restructuring the timers is verified to preserve them.
func TestTimerDeadlines(t *testing.T) {
	const (
		slot         = 2
		slotDuration = 12 * time.Second
		rounds       = 6
	)

	var (
		genesisTime = time.Unix(1_000_000, 0)
		slotStart   = genesisTime.Add(slot * slotDuration)
		// Attestations are due a third into the slot pre-gloas, proposals at its start.
		offsetFunc = func(duty core.Duty) time.Duration {
			if duty.Type == core.DutyAttester {
				return 4 * time.Second
			}

			return 0
		}
	)

	// roundDeadlines are a round's deadlines relative to the start of the slot.
	type roundDeadlines struct {
		Round int64  `json:"round"`
		First string `json:"first"` // Upon arming the round when the previous round times out.
		Rearm string `json:"rearm"` // Upon re-arming the round rearmAfter later.
	}

	results := make(map[string][]roundDeadlines)

	for _, typ := range []Type{TimerIncreasing, TimerLinear, TimerEagerDoubleLinear} {
		for _, duty := range []core.Duty{core.NewAttesterDuty(slot), core.NewProposerDuty(slot)} {
			for _, proposalTimeout := range []bool{true, false} {
				for _, zeroTiming := range []bool{false, true} {
					name := fmt.Sprintf("%s/%s/proposal_timeout=%v/zero_timing=%v", typ, duty.Type, proposalTimeout, zeroTiming)

					t.Run(name, func(t *testing.T) {
						if proposalTimeout {
							featureset.EnableForT(t, featureset.ProposalTimeout)
						} else {
							featureset.DisableForT(t, featureset.ProposalTimeout)
						}

						genesis, duration := genesisTime, slotDuration
						if zeroTiming {
							genesis, duration = time.Time{}, 0
						}

						clock := &recordingClock{FakeClock: clockwork.NewFakeClockAt(slotStart)}
						roundTimer := timerForT(duty, typ, genesis, duration, offsetFunc, clock)

						for i, deadlines := range armRounds(clock, roundTimer, slotStart, rounds) {
							results[name] = append(results[name], roundDeadlines{
								Round: int64(i + 1),
								First: deadlines.armed.String(),
								Rearm: deadlines.rearmed.String(),
							})
						}
					})
				}
			}
		}
	}

	testutil.RequireGoldenJSON(t, results)
}

// timerForT returns the round timer of the type for the duty, with the extensions applied as when
// selected by GetRoundTimerFunc.
func timerForT(duty core.Duty, typ Type, genesisTime time.Time, slotDuration time.Duration,
	offsetFunc core.SlotOffsetFunc, clock clockwork.Clock,
) RoundTimer {
	defs := map[Type]timerDef{
		TimerIncreasing:        incTimer(),
		TimerLinear:            linearTimer(),
		TimerEagerDoubleLinear: eagerDLinearTimer(),
	}

	timing := slotTiming{
		genesisTime:  genesisTime,
		slotDuration: slotDuration,
		slotOffset:   offsetFunc,
	}

	return newRoundTimer(duty, withExtensions(duty, defs[typ], featureExtensions()...), timing, clock)
}

// roundArming are a round's deadlines relative to the start of the slot, when armed and when
// re-armed 100ms later, as upon a justified pre-prepare.
type roundArming struct {
	armed   time.Duration
	rearmed time.Duration
}

// armRounds arms rounds 1 to n in turn, each when the previous one times out, starting at the
// start of the slot, re-arming each 100ms after arming it, and returns their deadlines.
func armRounds(clock *recordingClock, roundTimer RoundTimer, slotStart time.Time, n int64) []roundArming {
	const rearmAfter = 100 * time.Millisecond

	var (
		resp  []roundArming
		armAt = slotStart
	)

	for round := int64(1); round <= n; round++ {
		clock.Advance(armAt.Sub(clock.Now()))

		_, stop := roundTimer.Timer(round)
		armed := clock.deadline

		stop()
		clock.Advance(rearmAfter)

		_, stop = roundTimer.Timer(round)
		rearmed := clock.deadline

		stop()

		resp = append(resp, roundArming{armed: armed.Sub(slotStart), rearmed: rearmed.Sub(slotStart)})
		armAt = armed
	}

	return resp
}

// recordingClock is a fake clock recording the deadline of the last created timer.
type recordingClock struct {
	*clockwork.FakeClock

	deadline time.Time
}

func (c *recordingClock) NewTimer(d time.Duration) clockwork.Timer {
	c.deadline = c.Now().Add(d)

	return c.FakeClock.NewTimer(d)
}

func TestRoundDurations(t *testing.T) {
	tests := []struct {
		name      string
		durations roundDurations
		want      []time.Duration // Durations of rounds 1 onwards.
	}{
		{
			name:      "flat",
			durations: eagerDLinearTimer().durations,
			want:      []time.Duration{time.Second, time.Second, time.Second, time.Second},
		},
		{
			name:      "increasing",
			durations: incTimer().durations,
			want:      []time.Duration{time.Second, 1250 * time.Millisecond, 1500 * time.Millisecond, 1750 * time.Millisecond},
		},
		{
			name:      "linear",
			durations: linearTimer().durations,
			want:      []time.Duration{time.Second, 400 * time.Millisecond, 600 * time.Millisecond, 800 * time.Millisecond},
		},
		{
			name:      "steps then growth",
			durations: roundDurations{first: 4 * time.Second, step: time.Second, steps: 2, growth: time.Second},
			want:      []time.Duration{4 * time.Second, time.Second, time.Second, 2 * time.Second, 3 * time.Second, 4 * time.Second},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var end time.Duration

			require.Zero(t, test.durations.end(0), "end before the first round")

			for i, want := range test.want {
				round := int64(i + 1)
				end += want

				require.Equal(t, want, test.durations.duration(round), "duration of round %d", round)
				require.Equal(t, end, test.durations.end(round), "end of round %d", round)
			}
		})
	}
}

func TestProposalTimeout(t *testing.T) {
	require.True(t, proposalTimeout{}.appliesForDuty(core.NewProposerDuty(1)))
	require.False(t, proposalTimeout{}.appliesForDuty(core.NewAttesterDuty(1)))

	require.Equal(t, 500*time.Millisecond, proposalTimeout{}.onArm(1))
	require.Zero(t, proposalTimeout{}.onArm(2))

	def := withExtensions(core.NewProposerDuty(1), eagerDLinearTimer(), proposalTimeout{})
	require.Equal(t, []extension{doubleOnRearm{}, proposalTimeout{}}, def.extensions)

	def = withExtensions(core.NewAttesterDuty(1), eagerDLinearTimer(), proposalTimeout{})
	require.Equal(t, []extension{doubleOnRearm{}}, def.extensions)

	// Extensions leave the timer's round durations unchanged.
	require.Equal(t, eagerDLinearTimer().durations, def.durations)
}

func TestWithExtensionsDeduplicates(t *testing.T) {
	// Extensions declared by the timer and added again, or added twice, are only kept once, in the
	// order of their first occurrence.
	def := withExtensions(core.NewProposerDuty(1), eagerDLinearTimer(), doubleOnRearm{}, proposalTimeout{}, proposalTimeout{})
	require.Equal(t, []extension{doubleOnRearm{}, proposalTimeout{}}, def.extensions)
}

func TestFeatureExtensions(t *testing.T) {
	featureset.EnableForT(t, featureset.ProposalTimeout)
	require.Equal(t, []extension{proposalTimeout{}}, featureExtensions())

	featureset.DisableForT(t, featureset.ProposalTimeout)
	require.Empty(t, featureExtensions())
}

func TestTimerSelection(t *testing.T) {
	const (
		slot         = 2
		slotDuration = 12 * time.Second
	)

	var (
		genesisTime = time.Unix(1_000_000, 0)
		slotStart   = genesisTime.Add(slot * slotDuration)
		timing      = slotTiming{
			genesisTime:  genesisTime,
			slotDuration: slotDuration,
			// Attestations are due a third into the slot pre-gloas, proposals at its start.
			slotOffset: func(duty core.Duty) time.Duration {
				if duty.Type == core.DutyAttester {
					return 4 * time.Second
				}

				return 0
			},
		}
		ms = func(ms int64) time.Duration { return time.Duration(ms) * time.Millisecond }
	)

	// Each case is a configuration users can set with feature flags, on top of the defaults: the
	// stable eager_double_linear and proposal_timeout features enabled, the alpha linear feature disabled.
	tests := []struct {
		name           string
		enable         []featureset.Feature
		disable        []featureset.Feature
		duty           core.Duty
		wantType       Type
		wantExtensions []string
		want           []roundArming // Rounds 1 onwards, relative to the start of the slot.
	}{
		{
			name:           "attester, defaults",
			duty:           core.NewAttesterDuty(slot),
			wantType:       TimerEagerDoubleLinear,
			wantExtensions: []string{"double_on_rearm"},
			want:           []roundArming{{ms(5000), ms(6000)}, {ms(6000), ms(8000)}, {ms(7000), ms(10000)}},
		},
		{
			name:           "attester, linear enabled",
			enable:         []featureset.Feature{featureset.Linear},
			duty:           core.NewAttesterDuty(slot),
			wantType:       TimerEagerDoubleLinear,
			wantExtensions: []string{"double_on_rearm"},
			want:           []roundArming{{ms(5000), ms(6000)}, {ms(6000), ms(8000)}, {ms(7000), ms(10000)}},
		},
		{
			name:           "attester, eager double linear disabled",
			disable:        []featureset.Feature{featureset.EagerDoubleLinear},
			duty:           core.NewAttesterDuty(slot),
			wantType:       TimerIncreasing,
			wantExtensions: []string{"reset_on_rearm"},
			want:           []roundArming{{ms(1000), ms(1100)}, {ms(2250), ms(2350)}, {ms(3750), ms(3850)}},
		},
		{
			name:           "proposer, defaults",
			duty:           core.NewProposerDuty(slot),
			wantType:       TimerEagerDoubleLinear,
			wantExtensions: []string{"double_on_rearm", "proposal_timeout"},
			want:           []roundArming{{ms(1500), ms(3000)}, {ms(2500), ms(5000)}, {ms(3500), ms(7000)}},
		},
		{
			name:           "proposer, proposal timeout disabled",
			disable:        []featureset.Feature{featureset.ProposalTimeout},
			duty:           core.NewProposerDuty(slot),
			wantType:       TimerEagerDoubleLinear,
			wantExtensions: []string{"double_on_rearm"},
			want:           []roundArming{{ms(1000), ms(2000)}, {ms(2000), ms(4000)}, {ms(3000), ms(6000)}},
		},
		{
			name:           "proposer, eager double linear disabled",
			disable:        []featureset.Feature{featureset.EagerDoubleLinear},
			duty:           core.NewProposerDuty(slot),
			wantType:       TimerIncreasing,
			wantExtensions: []string{"reset_on_rearm", "proposal_timeout"},
			want:           []roundArming{{ms(1500), ms(1600)}, {ms(2750), ms(2850)}, {ms(4250), ms(4350)}},
		},
		{
			name:           "proposer, eager double linear and proposal timeout disabled",
			disable:        []featureset.Feature{featureset.EagerDoubleLinear, featureset.ProposalTimeout},
			duty:           core.NewProposerDuty(slot),
			wantType:       TimerIncreasing,
			wantExtensions: []string{"reset_on_rearm"},
			want:           []roundArming{{ms(1000), ms(1100)}, {ms(2250), ms(2350)}, {ms(3750), ms(3850)}},
		},
		{
			name:           "proposer, linear enabled",
			enable:         []featureset.Feature{featureset.Linear},
			duty:           core.NewProposerDuty(slot),
			wantType:       TimerLinear,
			wantExtensions: []string{"reset_on_rearm", "proposal_timeout"},
			want:           []roundArming{{ms(1500), ms(1600)}, {ms(1900), ms(2000)}, {ms(2500), ms(2600)}},
		},
		{
			name:           "proposer, linear enabled and proposal timeout disabled",
			enable:         []featureset.Feature{featureset.Linear},
			disable:        []featureset.Feature{featureset.ProposalTimeout},
			duty:           core.NewProposerDuty(slot),
			wantType:       TimerLinear,
			wantExtensions: []string{"reset_on_rearm"},
			want:           []roundArming{{ms(1000), ms(1100)}, {ms(1400), ms(1500)}, {ms(2000), ms(2100)}},
		},
		{
			name:           "proposer, linear enabled and eager double linear disabled",
			enable:         []featureset.Feature{featureset.Linear},
			disable:        []featureset.Feature{featureset.EagerDoubleLinear},
			duty:           core.NewProposerDuty(slot),
			wantType:       TimerLinear,
			wantExtensions: []string{"reset_on_rearm", "proposal_timeout"},
			want:           []roundArming{{ms(1500), ms(1600)}, {ms(1900), ms(2000)}, {ms(2500), ms(2600)}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, feature := range test.enable {
				featureset.EnableForT(t, feature)
			}

			for _, feature := range test.disable {
				featureset.DisableForT(t, feature)
			}

			clock := &recordingClock{FakeClock: clockwork.NewFakeClockAt(slotStart)}
			roundTimer := newRoundTimer(test.duty, selectTimer(test.duty), timing, clock)

			require.Equal(t, test.wantType, roundTimer.Type())
			require.Equal(t, test.wantExtensions, roundTimer.Extensions())
			require.Equal(t, test.want, armRounds(clock, roundTimer, slotStart, int64(len(test.want))))
		})
	}
}
