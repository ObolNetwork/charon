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
	"sync"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
)

func TestCancelledQueries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	db := NewMemDB(noopDeadliner{})

	const slot = 99

	var wg sync.WaitGroup

	// Enqueue queries of each type.

	wg.Add(1)
	go func() {
		_, err := db.AwaitAttestation(ctx, slot, 0)
		require.ErrorIs(t, err, context.Canceled)
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		_, err := db.AwaitAggAttestation(ctx, slot, eth2p0.Root{})
		require.ErrorIs(t, err, context.Canceled)
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		_, err := db.AwaitBeaconBlock(ctx, slot)
		require.ErrorIs(t, err, context.Canceled)
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		_, err := db.AwaitBlindedBeaconBlock(ctx, slot)
		require.ErrorIs(t, err, context.Canceled)
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		_, err := db.AwaitSyncContribution(ctx, slot, 0, eth2p0.Root{})
		require.ErrorIs(t, err, context.Canceled)
		wg.Done()
	}()

	cancel()  // Cancel the queries
	wg.Wait() // Wait for them to complete

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
