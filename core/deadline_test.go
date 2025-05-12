// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core_test

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

//go:generate go test .
func TestDeadliner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
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
	const lateFactor = 5

	ctx := context.Background()
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	genesis, err := bmock.Genesis(ctx, &eth2api.GenesisOpts{})
	require.NoError(t, err)
	genesisTime := genesis.Data.GenesisTime

	eth2Resp, err := bmock.Spec(ctx, &eth2api.SpecOpts{})
	require.NoError(t, err)
	slotDuration, ok := eth2Resp.Data["SECONDS_PER_SLOT"].(time.Duration)
	require.True(t, ok)

	deadlineFunc, submitDeadlineFunc, err := core.NewDutyDeadlineFunc(ctx, bmock)
	require.NoError(t, err)

	t.Run("exit duty", func(t *testing.T) {
		_, expires := deadlineFunc(core.NewVoluntaryExit(1))
		require.False(t, expires)
		_, expires = submitDeadlineFunc(core.NewVoluntaryExit(1))
		require.False(t, expires)
	})

	t.Run("builder registration duty", func(t *testing.T) {
		_, expires := deadlineFunc(core.NewBuilderRegistrationDuty(1))
		require.False(t, expires)
		_, expires = submitDeadlineFunc(core.NewBuilderRegistrationDuty(1))
		require.False(t, expires)
	})

	t.Run("proposer duty", func(t *testing.T) {
		d := core.NewProposerDuty(100)
		dt, expires := deadlineFunc(d)
		require.True(t, expires)
		require.Equal(t, dt, genesisTime.Add(slotDuration*time.Duration(d.Slot+lateFactor)))

		dt, expires = submitDeadlineFunc(d)
		require.True(t, expires)
		submissionLimit := slotDuration / 3
		require.Equal(t, dt, genesisTime.Add(slotDuration*time.Duration(d.Slot)).Add(submissionLimit))
	})

	t.Run("attester duty", func(t *testing.T) {
		d := core.NewAttesterDuty(100)
		dt, expires := deadlineFunc(d)
		require.True(t, expires)
		require.Equal(t, dt, genesisTime.Add(slotDuration*time.Duration(d.Slot+lateFactor)))

		dt, expires = submitDeadlineFunc(d)
		require.True(t, expires)
		submissionLimit := 2 * slotDuration / 3
		require.Equal(t, dt, genesisTime.Add(slotDuration*time.Duration(d.Slot)).Add(submissionLimit))
	})

	t.Run("sync message duty", func(t *testing.T) {
		d := core.NewSyncMessageDuty(100)
		dt, expires := deadlineFunc(d)
		require.True(t, expires)
		require.Equal(t, dt, genesisTime.Add(slotDuration*time.Duration(d.Slot+lateFactor)))

		dt, expires = submitDeadlineFunc(d)
		require.True(t, expires)
		submissionLimit := 2 * slotDuration / 3
		require.Equal(t, dt, genesisTime.Add(slotDuration*time.Duration(d.Slot)).Add(submissionLimit))
	})

	t.Run("aggregator duty", func(t *testing.T) {
		d := core.NewAggregatorDuty(100)
		dt, expires := deadlineFunc(d)
		require.True(t, expires)
		require.Equal(t, dt, genesisTime.Add(slotDuration*time.Duration(d.Slot+lateFactor)))

		dt, expires = submitDeadlineFunc(d)
		require.True(t, expires)
		submissionLimit := slotDuration
		require.Equal(t, dt, genesisTime.Add(slotDuration*time.Duration(d.Slot)).Add(submissionLimit))
	})

	t.Run("sync contribution duty", func(t *testing.T) {
		d := core.NewSyncContributionDuty(100)
		dt, expires := deadlineFunc(d)
		require.True(t, expires)
		require.Equal(t, dt, genesisTime.Add(slotDuration*time.Duration(d.Slot+lateFactor)))

		dt, expires = submitDeadlineFunc(d)
		require.True(t, expires)
		submissionLimit := slotDuration
		require.Equal(t, dt, genesisTime.Add(slotDuration*time.Duration(d.Slot)).Add(submissionLimit))
	})

	t.Run("randao duty", func(t *testing.T) {
		d := core.NewRandaoDuty(100)
		dt, expires := deadlineFunc(d)
		require.True(t, expires)
		require.Equal(t, dt, genesisTime.Add(slotDuration*time.Duration(d.Slot+lateFactor)))

		sdt, expires := submitDeadlineFunc(d)
		require.True(t, expires)
		require.Equal(t, dt, sdt)
	})
}

// sendDuties runs a goroutine which adds the duties to the deadliner channel.
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
		for _, d := range expiredDuties {
			if d == duty {
				return true
			}
		}

		return false
	}

	return expiredDuties, nonExpiredDuties, voluntaryExits, dutyExpired
}
