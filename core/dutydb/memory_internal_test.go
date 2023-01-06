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

package dutydb

import (
	"context"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
)

func TestCancelledQueries(t *testing.T) {
	ctx := context.Background()

	db := NewMemDB(noopDeadliner{})
	db.Shutdown()

	const slot = 99

	// Enqueue queries of each type.
	_, err := db.AwaitAttestation(ctx, slot, 0)
	require.ErrorContains(t, err, "shutdown")

	_, err = db.AwaitAggAttestation(ctx, slot, eth2p0.Root{})
	require.ErrorContains(t, err, "shutdown")

	_, err = db.AwaitBeaconBlock(ctx, slot)
	require.ErrorContains(t, err, "shutdown")

	_, err = db.AwaitBlindedBeaconBlock(ctx, slot)
	require.ErrorContains(t, err, "shutdown")

	_, err = db.AwaitSyncContribution(ctx, slot, 0, eth2p0.Root{})
	require.ErrorContains(t, err, "shutdown")

	// Ensure all queries are preset.
	require.NotEmpty(t, db.contribQueries)
	require.NotEmpty(t, db.attQueries)
	require.NotEmpty(t, db.proQueries)
	require.NotEmpty(t, db.aggQueries)
	require.NotEmpty(t, db.builderProQueries)

	// Resolve queries
	db.resolveAggQueriesUnsafe()
	db.resolveAttQueriesUnsafe()
	db.resolveContribQueriesUnsafe()
	db.resolveProQueriesUnsafe()
	db.resolveBuilderProQueriesUnsafe()

	// Ensure all queries are gone.
	require.Empty(t, db.contribQueries)
	require.Empty(t, db.attQueries)
	require.Empty(t, db.proQueries)
	require.Empty(t, db.aggQueries)
	require.Empty(t, db.builderProQueries)
}

type noopDeadliner struct{}

func (t noopDeadliner) Add(duty core.Duty) bool {
	return true
}

func (t noopDeadliner) C() <-chan core.Duty {
	return make(chan core.Duty)
}
