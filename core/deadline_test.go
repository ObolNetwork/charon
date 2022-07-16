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
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestDeadliner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bmock, err := beaconmock.New(
		beaconmock.WithGenesisTime(time.Now()),
		beaconmock.WithSlotDuration(time.Second),
	)
	require.NoError(t, err)

	deadliner, err := core.NewDeadliner(ctx, bmock)
	require.NoError(t, err)

	// It will take around 7 seconds to timeout these 3 duties
	expectedDuties := []core.Duty{
		core.NewAttesterDuty(1),
		core.NewAttesterDuty(2),
		core.NewAttesterDuty(3),
	}

	for _, duty := range expectedDuties {
		deadliner.Add(duty)
	}

	for _, duty := range expectedDuties {
		actualDuty := <-deadliner.C()
		require.Equal(t, duty, actualDuty)
	}
}
