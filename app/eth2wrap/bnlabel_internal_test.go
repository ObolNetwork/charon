// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
)

func TestSanitiseBeaconNodeAddr(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"http://10.0.0.1:5052", "http://10.0.0.1:5052"},
		{"10.0.0.1:5052", "http://10.0.0.1:5052"},
		{"httpbn:5052", "http://httpbn:5052"},
		{"https://user:secret@bn.example.com/apikey123?token=abc", "https://bn.example.com"},
		{"https://bn.example.com/eth/v1/", "https://bn.example.com"},
		{"http://[::1]:5052", "http://[::1]:5052"},
		{"http://", invalidBeaconNodeLabel},
		{"http://bad host:5052", invalidBeaconNodeLabel},
		{"https://" + strings.Repeat("a", 100) + ".com", ("https://" + strings.Repeat("a", 100))[:maxBeaconNodeLabelLen]},
	}

	for _, test := range tests {
		t.Run(test.addr, func(t *testing.T) {
			got := sanitiseBeaconNodeAddr(test.addr)
			require.Equal(t, test.want, got)
			require.NotContains(t, got, "secret")
			require.NotContains(t, got, "apikey")
			require.LessOrEqual(t, len(got), maxBeaconNodeLabelLen)
		})
	}
}

func TestBeaconNodeLabel(t *testing.T) {
	resetBeaconNodeLabelsForT()
	t.Cleanup(resetBeaconNodeLabelsForT)

	// Stable for the same address.
	require.Equal(t, "http://10.0.0.1:5052", BeaconNodeLabel("http://10.0.0.1:5052"))
	require.Equal(t, "http://10.0.0.1:5052", BeaconNodeLabel("http://10.0.0.1:5052"))

	// Different addresses on the same host don't collide.
	require.Equal(t, "https://bn.example.com", BeaconNodeLabel("https://bn.example.com/key1"))
	require.Equal(t, "https://bn.example.com#2", BeaconNodeLabel("https://bn.example.com/key2"))
	require.Equal(t, "https://bn.example.com#2", BeaconNodeLabel("https://bn.example.com/key2"))

	// Capped.
	for i := range 2 * maxBeaconNodeLabels {
		BeaconNodeLabel(fmt.Sprintf("http://10.1.0.%d:5052", i))
	}

	distinct := make(map[string]bool)
	for _, label := range bnLabels.byAddr {
		distinct[label] = true
	}

	require.Len(t, distinct, maxBeaconNodeLabels+1) // Including "other".
	require.True(t, distinct[otherBeaconNodeLabel])
	require.Equal(t, otherBeaconNodeLabel, BeaconNodeLabel("http://10.2.0.1:5052"))

	// Earlier addresses keep their label.
	require.Equal(t, "http://10.0.0.1:5052", BeaconNodeLabel("http://10.0.0.1:5052"))
}

// resetPerBeaconNodeMetrics resets the global per beacon node metrics, so tests can run repeatedly.
func resetPerBeaconNodeMetrics(t *testing.T) {
	t.Helper()

	bnRequestCount.Reset()
	bnErrorCount.Reset()
	bnFirstCount.Reset()
}

func TestInstrumentPerBeaconNode(t *testing.T) {
	resetPerBeaconNodeMetrics(t)
	resetBeaconNodeLabelsForT()
	t.Cleanup(resetBeaconNodeLabelsForT)

	const endpoint = "test_instrument_per_bn"

	newClient := func(addr string) Client {
		return &lazy{confAddress: addr}
	}

	errFail := errors.New("fail")

	work := instrumentPerBeaconNode(endpoint, func(_ context.Context, args provideArgs) (int, error) {
		if strings.Contains(args.client.(*lazy).confAddress, "bad") {
			return 0, errFail
		}

		return 1, nil
	})

	good := newClient("http://good:5052")
	bad := newClient("http://user:pass@bad:5052/key")

	_, err := work(t.Context(), provideArgs{client: good})
	require.NoError(t, err)
	_, err = work(t.Context(), provideArgs{client: bad})
	require.ErrorIs(t, err, errFail)

	// Cancelled requests count as requests but not as errors.
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()

	_, err = work(cancelled, provideArgs{client: bad})
	require.ErrorIs(t, err, errFail)

	// Requests that hit the caller's deadline count as errors.
	expired, cancelExpired := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancelExpired()

	_, err = work(expired, provideArgs{client: bad})
	require.ErrorIs(t, err, errFail)

	require.InDelta(t, 1, testutil.ToFloat64(bnRequestCount.WithLabelValues(endpoint, "http://good:5052")), 0)
	require.InDelta(t, 0, testutil.ToFloat64(bnErrorCount.WithLabelValues(endpoint, "http://good:5052")), 0)
	require.InDelta(t, 3, testutil.ToFloat64(bnRequestCount.WithLabelValues(endpoint, "http://bad:5052")), 0)
	require.InDelta(t, 2, testutil.ToFloat64(bnErrorCount.WithLabelValues(endpoint, "http://bad:5052")), 0)
}

func TestProvideCountsFirstResponse(t *testing.T) {
	resetPerBeaconNodeMetrics(t)
	resetBeaconNodeLabelsForT()
	t.Cleanup(resetBeaconNodeLabelsForT)

	const endpoint = "test_provide_first"

	clients := []Client{&lazy{confAddress: "http://a:5052"}, &lazy{confAddress: "http://b:5052"}}

	release := make(chan struct{})

	t.Cleanup(func() { close(release) })

	out, err := provide(t.Context(), endpoint, clients, nil,
		func(ctx context.Context, args provideArgs) (string, error) {
			if args.client.(*lazy).confAddress == "http://b:5052" {
				select { // b is slow, a always answers first.
				case <-release:
				case <-ctx.Done():
					return "", ctx.Err()
				}
			}

			return args.client.(*lazy).confAddress, nil
		}, nil, nil)
	require.NoError(t, err)
	require.Equal(t, "http://a:5052", out)

	require.InDelta(t, 1, testutil.ToFloat64(bnFirstCount.WithLabelValues(endpoint, "http://a:5052")), 0)
	require.InDelta(t, 0, testutil.ToFloat64(bnFirstCount.WithLabelValues(endpoint, "http://b:5052")), 0)
	require.InDelta(t, 0, testutil.ToFloat64(bnErrorCount.WithLabelValues(endpoint, "http://b:5052")), 0)
}
