// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package qbft

import (
	"io"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus/timer"
)

// TestRoundTimersFirstLeaderDown simulates a cluster whose first round leader is down, for each timer
// users can configure with feature flags, verifying the other peers decide in the second round, right
// after the first round times out. The simulation runs on a fake clock, so it doesn't wait in real time.
func TestRoundTimersFirstLeaderDown(t *testing.T) {
	const (
		nodes        = 4
		slot         = 1
		slotDuration = 12 * time.Second
		latency      = 10 * time.Millisecond
	)

	var (
		genesisTime = time.Unix(1_000_000, 0)
		slotStart   = genesisTime.Add(slot * slotDuration)
		// Duties start at the start of the slot, which is when the simulation starts.
		zeroOffset = func(core.Duty) time.Duration { return 0 }
	)

	tests := []struct {
		name     string
		enable   []featureset.Feature
		disable  []featureset.Feature
		dutyType core.DutyType
		wantType timer.Type
		// firstRoundEnd is when the first round times out, relative to the start of the slot.
		firstRoundEnd time.Duration
	}{
		{
			name:          "attester, defaults",
			dutyType:      core.DutyAttester,
			wantType:      timer.TimerEagerDoubleLinear,
			firstRoundEnd: time.Second,
		},
		{
			name:          "attester, eager double linear disabled",
			disable:       []featureset.Feature{featureset.EagerDoubleLinear},
			dutyType:      core.DutyAttester,
			wantType:      timer.TimerIncreasing,
			firstRoundEnd: time.Second,
		},
		{
			name:          "proposer, defaults",
			dutyType:      core.DutyProposer,
			wantType:      timer.TimerEagerDoubleLinear,
			firstRoundEnd: 1500 * time.Millisecond,
		},
		{
			name:          "proposer, proposal timeout disabled",
			disable:       []featureset.Feature{featureset.ProposalTimeout},
			dutyType:      core.DutyProposer,
			wantType:      timer.TimerEagerDoubleLinear,
			firstRoundEnd: time.Second,
		},
		{
			name:          "proposer, linear enabled",
			enable:        []featureset.Feature{featureset.Linear},
			dutyType:      core.DutyProposer,
			wantType:      timer.TimerLinear,
			firstRoundEnd: 1500 * time.Millisecond,
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

			duty := core.Duty{Slot: slot, Type: test.dutyType}
			firstLeader := leader(duty, 1, nodes)

			roundTimerFunc := func(clock clockwork.Clock) timer.RoundTimer {
				return timer.GetRoundTimerFuncForT(t, genesisTime, slotDuration, zeroOffset, clock)(duty)
			}
			require.Equal(t, test.wantType, roundTimerFunc(nil).Type())

			latencyPerPeer := make(map[int64]time.Duration)
			for peer := range int64(nodes) {
				latencyPerPeer[peer] = latency
			}

			// Peers log concurrently, so the discarded logs need a locked syncer.
			syncer := zapcore.Lock(zapcore.AddSync(io.Discard))

			results := testStrategySimulator(t, ssConfig{
				seed:           slot, // The simulated duty's slot.
				latencyPerPeer: latencyPerPeer,
				startByPeer:    map[int64]time.Duration{firstLeader: disabled},
				roundTimerFunc: roundTimerFunc,
				timeout:        3 * time.Second,
				startTime:      slotStart,
				dutyType:       test.dutyType,
			}, syncer)

			require.Len(t, results, nodes)

			for _, res := range results {
				if res.PeerIdx == firstLeader {
					require.False(t, res.Decided, "the first leader is down")
					continue
				}

				require.True(t, res.Decided, "peer %d didn't decide", res.PeerIdx)
				require.EqualValues(t, 2, res.Round, "peer %d", res.PeerIdx)
				require.GreaterOrEqual(t, res.Duration, test.firstRoundEnd, "peer %d decided before the first round timed out", res.PeerIdx)
				require.Less(t, res.Duration, test.firstRoundEnd+500*time.Millisecond, "peer %d", res.PeerIdx)
			}
		})
	}
}
