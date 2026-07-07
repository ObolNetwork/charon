// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package relay

import (
	"testing"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func TestDeletePeerMetrics(t *testing.T) {
	countersBefore := promtestutil.CollectAndCount(newConnsCounter)
	pingsBefore := promtestutil.CollectAndCount(peerPingLatency)

	// One peer with series in multiple clusters, including the empty pre-peerinfo cluster.
	newConnsCounter.WithLabelValues("test-peer1", "cluster1").Add(1)
	newConnsCounter.WithLabelValues("test-peer1", "cluster2").Add(1)
	newConnsCounter.WithLabelValues("test-peer1", "").Add(1)
	activeConnsCounter.WithLabelValues("test-peer1", "cluster1").Set(1)
	networkTXCounter.WithLabelValues("test-peer1", "cluster1").Add(1)
	networkRXCounter.WithLabelValues("test-peer1", "cluster1").Add(1)
	peerPingLatency.WithLabelValues("test-peer1", "cluster1").Observe(1)

	newConnsCounter.WithLabelValues("test-peer2", "cluster1").Add(1)

	require.Equal(t, countersBefore+4, promtestutil.CollectAndCount(newConnsCounter))
	require.Equal(t, pingsBefore+1, promtestutil.CollectAndCount(peerPingLatency))

	deletePeerMetrics("test-peer1")

	require.Equal(t, countersBefore+1, promtestutil.CollectAndCount(newConnsCounter))
	require.Equal(t, pingsBefore, promtestutil.CollectAndCount(peerPingLatency))

	deletePeerMetrics("test-peer2")

	require.Equal(t, countersBefore, promtestutil.CollectAndCount(newConnsCounter))
}
