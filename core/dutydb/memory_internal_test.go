// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dutydb

import (
	"context"
	"testing"

	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

func TestCancelledQueries(t *testing.T) {
	ctx := context.Background()

	db := NewMemDB(noopDeadliner{})
	db.Shutdown()

	const slot = 99

	// Enqueue queries of each type.
	_, err := db.AwaitAttestation(ctx, slot, 0)
	require.ErrorContains(t, err, "shutdown")

	_, err = db.AwaitAggAttestation(ctx, slot, eth2p0.Root{}, 0)
	require.ErrorContains(t, err, "shutdown")

	_, err = db.AwaitProposal(ctx, slot)
	require.ErrorContains(t, err, "shutdown")

	_, err = db.AwaitSyncContribution(ctx, slot, 0, eth2p0.Root{})
	require.ErrorContains(t, err, "shutdown")

	_, _, err = db.AwaitPayloadAttestationData(ctx, slot)
	require.ErrorContains(t, err, "shutdown")

	// Ensure all queries are preset.
	require.NotEmpty(t, db.contribQueries)
	require.NotEmpty(t, db.attQueries)
	require.NotEmpty(t, db.proQueries)
	require.NotEmpty(t, db.aggQueries)
	require.NotEmpty(t, db.payloadAttQueries)

	// Resolve queries
	db.resolveAggQueriesUnsafe()
	db.resolveAttQueriesUnsafe()
	db.resolveContribQueriesUnsafe()
	db.resolveProQueriesUnsafe()
	db.resolvePayloadAttQueriesUnsafe()

	// Ensure all queries are gone.
	require.Empty(t, db.contribQueries)
	require.Empty(t, db.attQueries)
	require.Empty(t, db.proQueries)
	require.Empty(t, db.aggQueries)
	require.Empty(t, db.payloadAttQueries)
}

// TestNoPayloadAttestationData asserts that only the zero value marks an agreed no-block slot,
// independent of which fork's data field is populated.
func TestNoPayloadAttestationData(t *testing.T) {
	require.True(t, noPayloadAttestationData(core.VersionedPayloadAttestationData{}))

	data, err := core.NewVersionedPayloadAttestationData(testutil.RandomVersionedPayloadAttestationData())
	require.NoError(t, err)
	require.False(t, noPayloadAttestationData(data))

	// A version without data is malformed, not the no-block marker.
	malformed := core.VersionedPayloadAttestationData{
		Version: eth2spec.DataVersionGloas,
	}
	require.False(t, noPayloadAttestationData(malformed))
}

type noopDeadliner struct{}

func (t noopDeadliner) Add(duty core.Duty) core.DeadlineStatus {
	return core.DeadlineScheduled
}

func (t noopDeadliner) C() <-chan core.Duty {
	return make(chan core.Duty)
}
