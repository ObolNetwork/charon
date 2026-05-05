// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core_test

import (
	"context"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

//go:generate go test .

func TestDeadliner(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	expiredDuties, nonExpiredDuties, voluntaryExits, dutyExpired := setupData(t)
	clock := clockwork.NewFakeClock()

	deadlineFuncProvider := func() func(duty core.Duty) (time.Time, bool) {
		startTime := clock.Now()

		return func(duty core.Duty) (time.Time, bool) {
			if duty.Type == core.DutyExit {
				return startTime.Add(time.Hour), true
			}

			if dutyExpired(duty) {
				return startTime.Add(-1 * time.Hour), true
			}

			return startTime.Add(time.Duration(duty.Slot) * time.Second), true
		}
	}

	deadliner := core.NewDeadlinerForT(ctx, t, deadlineFuncProvider(), clock)

	wg := &sync.WaitGroup{}

	// Add our duties to the deadliner.
	expectedFalseCh := make(chan bool, len(expiredDuties))
	expectedTrueCh := make(chan bool, len(nonExpiredDuties)+len(voluntaryExits))

	addDuties(t, wg, expiredDuties, expectedFalseCh, deadliner)
	addDuties(t, wg, nonExpiredDuties, expectedTrueCh, deadliner)
	addDuties(t, wg, voluntaryExits, expectedTrueCh, deadliner)

	// Wait till all the duties are added to the deadliner.
	wg.Wait()

	for range len(expiredDuties) {
		require.False(t, <-expectedFalseCh)
	}

	for range len(nonExpiredDuties) + len(voluntaryExits) {
		require.True(t, <-expectedTrueCh)
	}

	var maxSlot uint64
	for _, duty := range nonExpiredDuties {
		if maxSlot < duty.Slot {
			maxSlot = duty.Slot
		}
	}

	// Advance clock to trigger deadline of all non-expired duties.
	clock.Advance(time.Duration(maxSlot) * time.Second)

	var actualDuties []core.Duty
	for range len(nonExpiredDuties) {
		actualDuties = append(actualDuties, <-deadliner.C())
	}

	sort.Slice(actualDuties, func(i, j int) bool {
		return actualDuties[i].Slot < actualDuties[j].Slot
	})

	require.Equal(t, nonExpiredDuties, actualDuties)
}

func TestNewDutyDeadlineFunc(t *testing.T) {
	bmock, err := beaconmock.New(t.Context())
	require.NoError(t, err)

	genesisTime, err := eth2wrap.FetchGenesisTime(t.Context(), bmock)
	require.NoError(t, err)

	slotDuration, _, err := eth2wrap.FetchSlotsConfig(t.Context(), bmock)
	require.NoError(t, err)

	margin := slotDuration / 12
	currentSlot := uint64(time.Since(genesisTime) / slotDuration)
	now := genesisTime.Add(time.Duration(currentSlot) * slotDuration)

	deadlineFunc, err := core.NewDutyDeadlineFunc(t.Context(), bmock)
	require.NoError(t, err)

	t.Run("never expire", func(t *testing.T) {
		t.Run("exit", func(t *testing.T) {
			duty := core.NewVoluntaryExit(currentSlot)
			_, ok := deadlineFunc(duty)
			require.False(t, ok)
		})

		t.Run("builder registration", func(t *testing.T) {
			duty := core.NewBuilderRegistrationDuty(currentSlot)
			_, ok := deadlineFunc(duty)
			require.False(t, ok)
		})
	})

	tests := []struct {
		duty             core.Duty
		expectedDuration time.Duration
	}{
		{
			duty:             core.NewProposerDuty(currentSlot),
			expectedDuration: slotDuration/3 + margin,
		},
		{
			duty:             core.NewAttesterDuty(currentSlot),
			expectedDuration: 2*slotDuration + margin,
		},
		{
			duty:             core.NewAggregatorDuty(currentSlot),
			expectedDuration: 2*slotDuration + margin,
		},
		{
			duty:             core.NewPrepareAggregatorDuty(currentSlot),
			expectedDuration: 2*slotDuration + margin,
		},
		{
			duty:             core.NewSyncMessageDuty(currentSlot),
			expectedDuration: 2*slotDuration/3 + margin,
		},
		{
			duty:             core.NewSyncContributionDuty(currentSlot),
			expectedDuration: slotDuration + margin,
		},
		{
			duty:             core.NewRandaoDuty(currentSlot),
			expectedDuration: slotDuration/3 + margin,
		},
		{
			duty:             core.NewInfoSyncDuty(currentSlot),
			expectedDuration: slotDuration + margin,
		},
		{
			duty:             core.NewPrepareSyncContributionDuty(currentSlot),
			expectedDuration: slotDuration + margin,
		},
	}

	for _, tt := range tests {
		t.Run(tt.duty.Type.String(), func(t *testing.T) {
			now := now.Add(tt.expectedDuration - time.Millisecond)
			end, ok := deadlineFunc(tt.duty)
			require.True(t, ok, "duty should have a deadline")
			require.True(t, now.Before(end), "wrong duty deadline")
			require.Equal(t, time.Millisecond, end.Sub(now))
		})
	}
}

// addDuties runs a goroutine which adds the duties to the deadliner channel.
func addDuties(t *testing.T, wg *sync.WaitGroup, duties []core.Duty, expCh chan bool, deadliner core.Deadliner) {
	t.Helper()

	wg.Add(1)

	go func(duties []core.Duty, expCh chan bool) {
		defer wg.Done()

		for _, duty := range duties {
			res := deadliner.Add(duty)
			expCh <- res
		}
	}(duties, expCh)
}

// setupData sets up the duties to send to deadliner.
func setupData(t *testing.T) ([]core.Duty, []core.Duty, []core.Duty, func(core.Duty) bool) {
	t.Helper()

	expiredDuties := []core.Duty{
		core.NewAttesterDuty(1),
		core.NewProposerDuty(2),
		core.NewRandaoDuty(3),
	}

	nonExpiredDuties := []core.Duty{
		core.NewProposerDuty(1),
		core.NewAttesterDuty(2),
	}

	voluntaryExits := []core.Duty{
		core.NewVoluntaryExit(2),
		core.NewVoluntaryExit(4),
	}

	dutyExpired := func(duty core.Duty) bool {
		return slices.Contains(expiredDuties, duty)
	}

	return expiredDuties, nonExpiredDuties, voluntaryExits, dutyExpired
}

func TestDeadlinerNoDutyLossOnFullChannel(t *testing.T) {
	// This test verifies that no duties are lost when the deadlineChan buffer is full.
	//
	// Previously, a non-blocking select with a `default` case would silently drop duties
	// when the output channel was at capacity (outputBuffer = 10), logging only a warning.
	// The fix removes the `default` case, making the send blocking and guaranteeing
	// that every deadlined duty is eventually delivered to the consumer.

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	clock := clockwork.NewFakeClock()
	startTime := clock.Now()

	// numDuties exceeds outputBuffer (10) to guarantee the channel fills up
	// before the consumer starts reading, exercising the previously broken path.
	const numDuties = 12

	duties := make([]core.Duty, numDuties)
	for i := range numDuties {
		duties[i] = core.NewAttesterDuty(uint64(i + 1))
	}

	// Stagger deadlines by slot so Deadliner processes them one-by-one in order.
	deadlineFunc := func(duty core.Duty) (time.Time, bool) {
		return startTime.Add(time.Duration(duty.Slot) * time.Millisecond), true
	}

	deadliner := core.NewDeadlinerForT(ctx, t, deadlineFunc, clock)

	for _, duty := range duties {
		require.True(t, deadliner.Add(duty))
	}

	// Advance the clock past all deadlines in one shot.
	// With the old default-case code, duties 11 and 12 would be silently dropped
	// once the 10-slot buffer was full.
	clock.Advance(time.Duration(numDuties+1) * time.Millisecond)

	// Collect every duty. The per-iteration timeout detects a dropped duty.
	received := make([]core.Duty, 0, numDuties)
	for range numDuties {
		select {
		case duty := <-deadliner.C():
			received = append(received, duty)
		case <-time.After(5 * time.Second):
			require.Fail(t, "duty lost",
				"received %d/%d duties — remaining duties were silently dropped when channel was full",
				len(received), numDuties,
			)
		}
	}

	require.Len(t, received, numDuties, "all duties must be delivered without loss")
}
