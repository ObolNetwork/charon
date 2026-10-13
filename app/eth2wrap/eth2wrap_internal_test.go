// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/retry"
)

// TestNodeVersionV2Refresh covers a beacon node that reports its execution client only after its
// version was first fetched, e.g. when they start together. The execution client must show up once
// the eth2http service clears its static values cache, without restarting.
func TestNodeVersionV2Refresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var withEE atomic.Bool

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			switch r.URL.Path {
			case "/eth/v1/node/version":
				_, _ = w.Write([]byte(`{"data":{"version":"Lighthouse/v8.0.0"}}`))
			case "/eth/v1/node/syncing":
				_, _ = w.Write([]byte(`{"data":{"head_slot":"100","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}`))
			case "/eth/v2/node/version":
				ee := ""
				if withEE.Load() {
					ee = `,"execution_client":{"code":"GE","name":"Geth","version":"v1.16.0","commit":"12345678"}`
				}

				_, _ = fmt.Fprintf(w, `{"data":{"beacon_node":{"code":"LH","name":"Lighthouse","version":"v8.0.0","commit":"abcdef01"}%s}}`, ee)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		})

		// Serve in-memory, since time in the bubble only advances while no goroutine waits on the network.
		httpCl := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, r)

			return rec.Result(), nil
		})}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		cl, err := Instrument([]Client{
			newBeaconClient(ctx, time.Second, [4]byte{}, nil, "http://beacon-node", eth2http.WithHTTPClient(httpCl)),
		}, nil)
		require.NoError(t, err)

		executionClient := func() *apiv1.ClientVersion {
			resp, err := cl.NodeVersionV2(ctx, &eth2api.NodeVersionV2Opts{})
			require.NoError(t, err)

			return resp.Data.ExecutionClient
		}

		require.Nil(t, executionClient())

		withEE.Store(true)
		require.Nil(t, executionClient(), "expected cached version")

		// The eth2http service clears its static values every 5 minutes.
		time.Sleep(5 * time.Minute)
		synctest.Wait()

		ee := executionClient()
		require.NotNil(t, ee, "execution client didn't refresh")
		require.Equal(t, "Geth", ee.Name)
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// TestConnectionStateRecovery covers duty requests after the eth2http service's periodic connection
// state ping found a beacon node slow or syncing. The service then fails requests without querying
// the node until a request's own ping succeeds, and concurrent requests fail while that ping is in
// flight, so duties rely on retries to recover.
func TestConnectionStateRecovery(t *testing.T) {
	t.Parallel()

	const (
		timeout  = 500 * time.Millisecond
		deadline = 2 * time.Second
		requests = 20
	)

	slowPing := func(bn *fakeBeaconNode) { bn.syncingDelay.Store(int64(2 * timeout)) }
	syncing := func(bn *fakeBeaconNode) { bn.syncing.Store(true) }
	healthy := func(bn *fakeBeaconNode) {
		bn.syncingDelay.Store(0)
		bn.syncing.Store(false)
	}
	unchanged := func(*fakeBeaconNode) {}

	tests := []struct {
		name string
		// nodes is the number of beacon nodes, the first one is pinged.
		nodes int
		// beforePing and afterPing modify the first node around the ping.
		beforePing func(*fakeBeaconNode)
		afterPing  func(*fakeBeaconNode)
		// expectSuccess is whether the requests succeed within the deadline.
		expectSuccess bool
	}{
		{
			name:          "ping timed out, node recovered",
			nodes:         1,
			beforePing:    slowPing,
			afterPing:     healthy,
			expectSuccess: true,
		},
		{
			name:          "ping found node syncing, node synced",
			nodes:         1,
			beforePing:    syncing,
			afterPing:     healthy,
			expectSuccess: true,
		},
		{
			name:          "ping keeps timing out",
			nodes:         1,
			beforePing:    slowPing,
			afterPing:     unchanged,
			expectSuccess: false,
		},
		{
			name:          "ping timed out, other node healthy",
			nodes:         2,
			beforePing:    slowPing,
			afterPing:     unchanged,
			expectSuccess: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var (
				bns     []*fakeBeaconNode
				clients []Client
			)

			for range test.nodes {
				bn := newFakeBeaconNode(t)
				bns = append(bns, bn)
				clients = append(clients, newBeaconClient(t.Context(), timeout, [4]byte{}, nil, bn.URL))
			}

			// Create the lazy clients individually, since a multi client stops at the first response.
			for _, c := range clients {
				_, err := c.AttestationData(t.Context(), &eth2api.AttestationDataOpts{Slot: 1})
				require.NoError(t, err)
			}

			cl, err := Instrument(clients, nil)
			require.NoError(t, err)

			pinged := bns[0]
			svc := eth2Service(t, clients[0])

			test.beforePing(pinged)
			svc.CheckConnectionState(t.Context())
			require.False(t, svc.IsSynced())
			test.afterPing(pinged)

			pinged.attDataHits.Store(0)

			retryer := retry.New(func(deadline time.Time) (time.Time, bool) {
				return deadline, true
			})

			var (
				wg        sync.WaitGroup
				successes atomic.Int64
			)

			for i := range requests {
				wg.Go(func() {
					retryer.DoAsync(t.Context(), time.Now().Add(deadline), "test", "attestation_data", func(ctx context.Context) error {
						_, err := cl.AttestationData(ctx, &eth2api.AttestationDataOpts{Slot: eth2p0.Slot(10 + i)})
						if err != nil {
							return err
						}

						successes.Add(1)

						return nil
					})
				})
			}

			wg.Wait()

			if test.expectSuccess {
				require.EqualValues(t, requests, successes.Load())
			} else {
				require.Zero(t, successes.Load())
				require.Zero(t, pinged.attDataHits.Load(), "service queried node it considers inactive")
			}
		})
	}
}

// fakeBeaconNode is a beacon node serving node version and attestation data, with a controllable
// node syncing endpoint. Like real beacon nodes, it doesn't serve attestation data while syncing.
type fakeBeaconNode struct {
	URL          string
	syncingDelay atomic.Int64 // time.Duration
	syncing      atomic.Bool
	attDataHits  atomic.Int64
}

func newFakeBeaconNode(t *testing.T) *fakeBeaconNode {
	t.Helper()

	bn := new(fakeBeaconNode)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/eth/v1/node/version":
			_, _ = w.Write([]byte(`{"data":{"version":"Lighthouse/v8.0.0"}}`))
		case "/eth/v1/node/syncing":
			select {
			case <-time.After(time.Duration(bn.syncingDelay.Load())):
			case <-r.Context().Done():
				return
			}

			if bn.syncing.Load() {
				_, _ = w.Write([]byte(`{"data":{"head_slot":"100","sync_distance":"50","is_syncing":true,"is_optimistic":false,"el_offline":false}}`))
			} else {
				_, _ = w.Write([]byte(`{"data":{"head_slot":"100","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}`))
			}
		case "/eth/v1/config/spec":
			_, _ = w.Write([]byte(`{"data":{"SLOTS_PER_EPOCH":"32","ELECTRA_FORK_EPOCH":"0"}}`))
		case "/eth/v1/validator/attestation_data":
			bn.attDataHits.Add(1)

			if bn.syncing.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"code":503,"message":"Beacon node is currently syncing"}`))

				return
			}

			root := "0x" + strings.Repeat("00", 32)
			_, _ = fmt.Fprintf(w, `{"data":{"slot":"%s","index":"0","beacon_block_root":"%s","source":{"epoch":"1","root":"%s"},"target":{"epoch":"2","root":"%s"}}}`,
				r.URL.Query().Get("slot"), root, root, root)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	bn.URL = srv.URL

	return bn
}

// eth2Service returns the eth2http service of a created lazy beacon client.
func eth2Service(t *testing.T, cl Client) *eth2http.Service {
	t.Helper()

	l, ok := cl.(*lazy)
	require.True(t, ok)

	inner, ok := l.getClient()
	require.True(t, ok)

	adapter, ok := inner.(*httpAdapter)
	require.True(t, ok)

	return adapter.Service
}
