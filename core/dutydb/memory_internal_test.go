// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

	_, err = db.AwaitAggAttestationV2(ctx, slot, eth2p0.Root{})
	require.ErrorContains(t, err, "shutdown")

	_, err = db.AwaitProposal(ctx, slot)
	require.ErrorContains(t, err, "shutdown")

	_, err = db.AwaitSyncContribution(ctx, slot, 0, eth2p0.Root{})
	require.ErrorContains(t, err, "shutdown")

	// Ensure all queries are preset.
	require.NotEmpty(t, db.contribQueries)
	require.NotEmpty(t, db.attQueries)
	require.NotEmpty(t, db.proQueries)
	require.NotEmpty(t, db.aggQueriesV2)

	// Resolve queries
	db.resolveAggQueriesV2Unsafe()
	db.resolveAttQueriesUnsafe()
	db.resolveContribQueriesUnsafe()
	db.resolveProQueriesUnsafe()

	// Ensure all queries are gone.
	require.Empty(t, db.contribQueries)
	require.Empty(t, db.attQueries)
	require.Empty(t, db.proQueries)
	require.Empty(t, db.aggQueriesV2)
}

type noopDeadliner struct{}

func (t noopDeadliner) Add(duty core.Duty) bool {
	return true
}

func (t noopDeadliner) C() <-chan core.Duty {
	return make(chan core.Duty)
}
