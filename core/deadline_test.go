// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core_test

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
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
	addDuties(t, wg, expiredDuties, false, deadliner)
	addDuties(t, wg, nonExpiredDuties, true, deadliner)
	addDuties(t, wg, voluntaryExits, true, deadliner)

	// Wait till all the duties are added to the deadliner.
	wg.Wait()

	var maxSlot uint64
	for _, duty := range nonExpiredDuties {
		if maxSlot < duty.Slot {
			maxSlot = duty.Slot
		}
	}

	// Advance clock to trigger deadline of all non-expired duties.
	clock.Advance(time.Duration(maxSlot) * time.Second)

	var actualDuties []core.Duty
	for i := 0; i < len(nonExpiredDuties); i++ {
		actualDuties = append(actualDuties, <-deadliner.C())
	}

	sort.Slice(actualDuties, func(i, j int) bool {
		return actualDuties[i].Slot < actualDuties[j].Slot
	})

	require.Equal(t, nonExpiredDuties, actualDuties)
}

// sendDuties runs a goroutine which adds the duties to the deadliner channel.
func addDuties(t *testing.T, wg *sync.WaitGroup, duties []core.Duty, expected bool, deadliner core.Deadliner) {
	t.Helper()

	wg.Add(1)
	go func(duties []core.Duty, expected bool) {
		defer wg.Done()
		for _, duty := range duties {
			require.Equal(t, deadliner.Add(duty), expected)
		}
	}(duties, expected)
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
		core.NewBuilderProposerDuty(3),
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
