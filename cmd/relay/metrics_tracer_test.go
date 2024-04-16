// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package relay_test

import (
	"strings"
	"testing"

	pbv2 "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/pb"
	p2p_relay "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/promauto"
	"github.com/obolnetwork/charon/cmd/relay"
)

func TestMetricsTracer(t *testing.T) {
	// The test runs both charon and libp2p MetricsTracer instances
	// and compares the metric values produced by both.
	// The only difference is metric namespace and name prefixes.

	charonReg, err := promauto.NewRegistry(prometheus.Labels{})
	require.NoError(t, err)
	charonMT := relay.NewMetricsTracer(charonReg)

	libp2pReg, err := promauto.NewRegistry(prometheus.Labels{})
	require.NoError(t, err)
	libp2pMT := p2p_relay.NewMetricsTracer(p2p_relay.WithRegisterer(libp2pReg))

	charonMT.RelayStatus(true)
	libp2pMT.RelayStatus(true)
	charonMT.BytesTransferred(100)
	libp2pMT.BytesTransferred(100)
	charonMT.ConnectionOpened()
	libp2pMT.ConnectionOpened()
	charonMT.ConnectionClosed(0)
	libp2pMT.ConnectionClosed(0)
	charonMT.ReservationRequestHandled(pbv2.Status_CONNECTION_FAILED)
	libp2pMT.ReservationRequestHandled(pbv2.Status_CONNECTION_FAILED)
	charonMT.ReservationAllowed(true)
	libp2pMT.ReservationAllowed(true)
	charonMT.ConnectionRequestHandled(pbv2.Status_CONNECTION_FAILED)
	libp2pMT.ConnectionRequestHandled(pbv2.Status_CONNECTION_FAILED)
	charonMT.ReservationClosed(123)
	libp2pMT.ReservationClosed(123)

	charonMetrics, err := charonReg.Gather()
	require.NoError(t, err)

	libp2pMetrics, err := libp2pReg.Gather()
	require.NoError(t, err)

	libp2pMetricsMap := make(map[string][]string)
	for _, lm := range libp2pMetrics {
		if strings.HasPrefix(lm.GetName(), "libp2p_relaysvc_") {
			name := strings.TrimPrefix(lm.GetName(), "libp2p_relaysvc_")
			var vals []string
			for _, m := range lm.GetMetric() {
				// timing fields go always last, safe to trim as they will differ
				vals = append(vals, strings.Split(m.String(), "seconds:")[0])
			}
			libp2pMetricsMap[name] = vals
		}
	}

	for _, cm := range charonMetrics {
		if strings.HasPrefix(cm.GetName(), "relay_p2p_int_") {
			name := strings.TrimPrefix(cm.GetName(), "relay_p2p_int_")
			charonVals := cm.GetMetric()
			libp2pVals := libp2pMetricsMap[name]
			for i := 0; i < len(charonVals); i++ {
				exp := strings.Split(charonVals[i].String(), "seconds:")[0]
				require.Equal(t, exp, libp2pVals[i])
			}
		}
	}
}
