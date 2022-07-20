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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
)

func TestDeadliner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	deadlineFuncProvider := func() func(duty core.Duty) time.Time {
		return func(duty core.Duty) time.Time {
			if duty.Type == core.DutyExit {
				// Do not timeout exit duties.
				return time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
			}

			return time.Now().Add(time.Millisecond * time.Duration(duty.Slot))
		}
	}

	deadliner := core.NewDeadliner(ctx, deadlineFuncProvider())

	expectedDuties := []core.Duty{
		core.NewVoluntaryExit(2),
		core.NewAttesterDuty(2),
		core.NewAttesterDuty(1),
		core.NewAttesterDuty(3),
	}

	for _, duty := range expectedDuties {
		deadliner.Add(duty)
	}

	var actualDuties []core.Duty
	for i := 0; i < len(expectedDuties)-1; i++ {
		actualDuty := <-deadliner.C()
		actualDuties = append(actualDuties, actualDuty)
	}

	require.Equal(t, len(expectedDuties), len(actualDuties)+1)

	// Since DutyExit doesn't timeout, we won't receive it from the deadliner.
	require.NotEqual(t, expectedDuties[0], actualDuties[0])

	// AttesterDuty for Slot 1 times out before AttesterDuty for Slot 2
	require.Equal(t, expectedDuties[2], actualDuties[0])
	require.Equal(t, expectedDuties[1], actualDuties[1])
	require.Equal(t, expectedDuties[3], actualDuties[2])
}
