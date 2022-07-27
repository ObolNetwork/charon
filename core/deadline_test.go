// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

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

func TestDeadliner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	expiredDuties, nonExpiredDuties, voluntaryExits, dutyExpired := setupData(t)
	clock := clockwork.NewFakeClock()

	deadlineFuncProvider := func() func(duty core.Duty) time.Time {
		startTime := clock.Now()
		return func(duty core.Duty) time.Time {
			if duty.Type == core.DutyExit {
				return startTime.Add(time.Hour)
			}

			if dutyExpired(duty) {
				return startTime.Add(-1 * time.Hour)
			}

			return startTime.Add(time.Duration(duty.Slot) * time.Second)
		}
	}

	deadliner := core.NewForT(ctx, t, deadlineFuncProvider(), clock)

	wg := &sync.WaitGroup{}

	// Add our duties to the deadliner.
	addDuties(t, wg, expiredDuties, false, deadliner)
	addDuties(t, wg, nonExpiredDuties, true, deadliner)
	addDuties(t, wg, voluntaryExits, true, deadliner)

	// Wait till all the duties are added to the deadliner.
	wg.Wait()

	var actualDuties []core.Duty
	for i := 0; i < len(nonExpiredDuties); i++ {
		// Advance clock by 1 second to trigger deadline of duties.
		clock.Advance(time.Second)
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
