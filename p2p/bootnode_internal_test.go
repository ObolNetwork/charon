// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testRelayAddr = "/ip4/1.2.3.4/tcp/3030/p2p/16Uiu2HAm1bSDxrCubda6Esz3NkXamvzEjQh4jzMp1PdckJwwMcuw"

// paddedAddrsJSON returns a valid json multiaddr array padded with trailing
// whitespace to exactly size bytes.
func paddedAddrsJSON(t *testing.T, size int) []byte {
	t.Helper()

	b, err := json.Marshal([]string{testRelayAddr})
	require.NoError(t, err)
	require.Less(t, len(b), size)

	return append(b, strings.Repeat(" ", size-len(b))...)
}

// TestQueryRelayAddrsBoundsResponse asserts that a relay streaming an endless response
// cannot make charon read an unbounded amount of it into memory.
func TestQueryRelayAddrsBoundsResponse(t *testing.T) {
	var written atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := []byte(strings.Repeat("a", 1<<12))
		for r.Context().Err() == nil {
			n, err := w.Write(chunk)
			written.Add(int64(n))

			if err != nil {
				return
			}

			w.(http.Flusher).Flush()
		}
	}))
	defer srv.Close()

	// Cancel as soon as the read returns, so the server cannot keep writing while the
	// query backs off for another attempt.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := queryRelayAddrs(ctx, srv.URL, cancel, "lockhash", "uuid")
	require.ErrorContains(t, err, "timeout querying relay addresses")

	// The server writes into the socket buffers beyond what charon reads, so allow generous
	// slack. Without the limit this grows unbounded until the context deadline.
	require.Less(t, written.Load(), int64(8<<20),
		"relay response read was not bounded by maxRelayResponseSize")
}

func TestQueryRelayAddrs(t *testing.T) {
	// writeValid responds with a valid json multiaddr array.
	writeValid := func(t *testing.T, w http.ResponseWriter, _ *http.Request) {
		t.Helper()
		require.NoError(t, json.NewEncoder(w).Encode([]string{testRelayAddr}))
	}

	// writeOversized responds with an otherwise valid body padded just over the accepted maximum.
	// The body stays valid json so that the size limit is what rejects it, not the parser.
	writeOversized := func(t *testing.T, w http.ResponseWriter, _ *http.Request) {
		t.Helper()
		_, _ = w.Write(paddedAddrsJSON(t, maxRelayResponseSize+1))
	}

	// writeAtLimit responds with a valid body padded to exactly the accepted maximum.
	writeAtLimit := func(t *testing.T, w http.ResponseWriter, _ *http.Request) {
		t.Helper()
		_, _ = w.Write(paddedAddrsJSON(t, maxRelayResponseSize))
	}

	// writeUnbounded streams a body until the client stops reading and closes the connection.
	// Without a limit on the client side, this never completes.
	writeUnbounded := func(_ *testing.T, w http.ResponseWriter, r *http.Request) {
		chunk := []byte(strings.Repeat("a", 1<<10))
		for r.Context().Err() == nil {
			if _, err := w.Write(chunk); err != nil {
				return
			}

			w.(http.Flusher).Flush()
		}
	}

	writeNonOK := func(_ *testing.T, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
	}

	tests := []struct {
		name string
		// handlers is applied per request attempt; the last one repeats.
		handlers []func(*testing.T, http.ResponseWriter, *http.Request)
	}{
		{
			name:     "valid response",
			handlers: []func(*testing.T, http.ResponseWriter, *http.Request){writeValid},
		},
		{
			name:     "oversized response then valid",
			handlers: []func(*testing.T, http.ResponseWriter, *http.Request){writeOversized, writeValid},
		},
		{
			name:     "response at exactly the limit",
			handlers: []func(*testing.T, http.ResponseWriter, *http.Request){writeAtLimit},
		},
		{
			name:     "unbounded response then valid",
			handlers: []func(*testing.T, http.ResponseWriter, *http.Request){writeUnbounded, writeValid},
		},
		{
			name:     "non-200 response then valid",
			handlers: []func(*testing.T, http.ResponseWriter, *http.Request){writeNonOK, writeValid},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var attempt atomic.Int64

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				idx := min(int(attempt.Add(1))-1, len(test.handlers)-1)
				test.handlers[idx](t, w, r)
			}))
			defer srv.Close()

			// The context bounds the whole test; a hanging read fails it rather than hanging forever.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			addrs, err := queryRelayAddrs(ctx, srv.URL, func() {}, "lockhash", "uuid")
			require.NoError(t, err)
			require.Len(t, addrs, 1)
			require.Equal(t, testRelayAddr, addrs[0].String())
			require.EqualValues(t, len(test.handlers), attempt.Load())
		})
	}
}
