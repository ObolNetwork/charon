// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package scheduler

import (
	"testing"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
)

func TestMetricSubmitterSweep(t *testing.T) {
	submit, sweep := newMetricSubmitter()

	pubkey1 := testutil.RandomCorePubKey(t)
	pubkey2 := testutil.RandomCorePubKey(t)

	before := promtestutil.CollectAndCount(balanceGauge)

	submit(pubkey1, 1, "active")
	submit(pubkey2, 1, "active")
	sweep()

	require.Equal(t, before+2, promtestutil.CollectAndCount(balanceGauge))

	// pubkey2 not submitted since the previous sweep, its series must be deleted.
	submit(pubkey1, 2, "active")
	sweep()

	require.Equal(t, before+1, promtestutil.CollectAndCount(balanceGauge))

	// No validators submitted at all, all series must be deleted.
	sweep()

	require.Equal(t, before, promtestutil.CollectAndCount(balanceGauge))
}
