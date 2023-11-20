// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestMulti(t *testing.T) {
	closedErr := errors.New("closed2")

	tests := []struct {
		name   string
		handle func(cl1Resp, cl2Resp chan uint64, ctxCancel context.CancelFunc)
		expErr error
		expRes uint64
	}{
		{
			name: "cl1 only",
			handle: func(cl1Resp, _ chan uint64, _ context.CancelFunc) {
				cl1Resp <- 99
			},
			expRes: 99,
		},
		{
			name: "cl2 only",
			handle: func(_, cl2Resp chan uint64, _ context.CancelFunc) {
				cl2Resp <- 99
			},
			expRes: 99,
		},
		{
			name: "ctx cancel",
			handle: func(_, _ chan uint64, ctxCancel context.CancelFunc) {
				ctxCancel()
			},
			expErr: context.Canceled,
		},
		{
			name: "cl1 error, cl2 ok",
			handle: func(cl1, cl2 chan uint64, _ context.CancelFunc) {
				close(cl1)
				cl2 <- 99
			},
			expRes: 99,
		},
		{
			name: "all error",
			handle: func(cl1, cl2 chan uint64, _ context.CancelFunc) {
				close(cl1)
				close(cl2)
			},
			expErr: closedErr,
		},
		{
			name: "cl1 error, ctx cancel",
			handle: func(cl1, _ chan uint64, cancel context.CancelFunc) {
				close(cl1)
				cancel()
			},
			expErr: context.Canceled,
		},
		{
			name: "cl2 before cl1",
			handle: func(cl1, cl2 chan uint64, cancel context.CancelFunc) {
				cl2 <- 99

				time.Sleep(time.Millisecond)
				cl1 <- 98 // This might flap?
			},
			expRes: 99,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			cl1, err := beaconmock.New()
			require.NoError(t, err)
			cl2, err := beaconmock.New()
			require.NoError(t, err)

			cl1Resp := make(chan uint64)
			cl2Resp := make(chan uint64)

			cl1.SlotsPerEpochFunc = func(ctx context.Context) (uint64, error) {
				select {
				case <-ctx.Done():
					return 0, ctx.Err()
				case resp, ok := <-cl1Resp:
					if !ok {
						return 0, closedErr
					}

					return resp, nil
				}
			}
			cl2.SlotsPerEpochFunc = func(ctx context.Context) (uint64, error) {
				select {
				case <-ctx.Done():
					return 0, ctx.Err()
				case resp, ok := <-cl2Resp:
					if !ok {
						return 0, closedErr
					}

					return resp, nil
				}
			}

			eth2Cl, err := eth2wrap.Instrument(cl1, cl2)
			require.NoError(t, err)

			go test.handle(cl1Resp, cl2Resp, cancel)

			resp, err := eth2Cl.SlotsPerEpoch(ctx)
			require.ErrorIs(t, err, test.expErr)
			require.Equal(t, test.expRes, resp)
		})
	}
}

func TestSyncState(t *testing.T) {
	cl1, err := beaconmock.New()
	require.NoError(t, err)
	cl2, err := beaconmock.New()
	require.NoError(t, err)

	cl1.NodeSyncingFunc = func(ctx context.Context, opts *eth2api.NodeSyncingOpts) (*eth2v1.SyncState, error) {
		return &eth2v1.SyncState{IsSyncing: false}, nil
	}
	cl2.NodeSyncingFunc = func(ctx context.Context, opts *eth2api.NodeSyncingOpts) (*eth2v1.SyncState, error) {
		return &eth2v1.SyncState{IsSyncing: true}, nil
	}

	eth2Cl, err := eth2wrap.Instrument(cl1, cl2)
	require.NoError(t, err)

	resp, err := eth2Cl.NodeSyncing(context.Background(), opts)
	require.NoError(t, err)
	require.False(t, resp.Data.IsSyncing)
}

func TestErrors(t *testing.T) {
	ctx := context.Background()
	t.Run("network dial error", func(t *testing.T) {
		cl, err := eth2wrap.NewMultiHTTP(time.Hour, "localhost:22222")
		require.NoError(t, err)

		_, err = cl.SlotsPerEpoch(ctx)
		log.Error(ctx, "See this error log for fields", err)
		require.Error(t, err)
		require.ErrorContains(t, err, "beacon api new eth2 client: network operation error: dial: connect: connection refused")
	})

	// Test http server that just hangs until request cancelled
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))

	t.Run("http timeout", func(t *testing.T) {
		cl, err := eth2wrap.NewMultiHTTP(time.Millisecond, srv.URL)
		require.NoError(t, err)

		_, err = cl.SlotsPerEpoch(ctx)
		log.Error(ctx, "See this error log for fields", err)
		require.Error(t, err)
		require.ErrorContains(t, err, "beacon api new eth2 client: http request timeout: context deadline exceeded")
	})

	t.Run("caller cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(ctx)
		cancel()

		cl, err := eth2wrap.NewMultiHTTP(time.Millisecond, srv.URL)
		require.NoError(t, err)

		_, err = cl.SlotsPerEpoch(ctx)
		log.Error(ctx, "See this error log for fields", err)
		require.Error(t, err)
		require.ErrorContains(t, err, "beacon api slots_per_epoch: context canceled")
	})

	t.Run("zero net op error", func(t *testing.T) {
		bmock, err := beaconmock.New()
		require.NoError(t, err)
		bmock.GenesisTimeFunc = func(context.Context) (time.Time, error) {
			return time.Time{}, new(net.OpError)
		}
		eth2Cl, err := eth2wrap.Instrument(bmock)
		require.NoError(t, err)

		_, err = eth2Cl.GenesisTime(ctx)
		log.Error(ctx, "See this error log for fields", err)
		require.Error(t, err)
		require.ErrorContains(t, err, "beacon api genesis_time: network operation error: :")
	})

	t.Run("eth2api error", func(t *testing.T) {
		bmock, err := beaconmock.New()
		require.NoError(t, err)
		bmock.SignedBeaconBlockFunc = func(_ context.Context, blockID string) (*eth2spec.VersionedSignedBeaconBlock, error) {
			return nil, &eth2api.Error{
				Method:     http.MethodGet,
				Endpoint:   fmt.Sprintf("/eth/v2/beacon/blocks/%s", blockID),
				StatusCode: http.StatusNotFound,
				Data:       []byte(fmt.Sprintf(`{"code":404,"message":"NOT_FOUND: beacon block at slot %s","stacktraces":[]}`, blockID)),
			}
		}

		eth2Cl, err := eth2wrap.Instrument(bmock)
		require.NoError(t, err)

		_, err = eth2Cl.SignedBeaconBlock(ctx, &eth2api.SignedBeaconBlockOpts{Block: "123"})
		log.Error(ctx, "See this error log for fields", err)
		require.Error(t, err)
		require.ErrorContains(t, err, "nok http response")
	})
}

func TestCtxCancel(t *testing.T) {
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithCancel(context.Background())

		bmock, err := beaconmock.New()
		require.NoError(t, err)
		eth2Cl, err := eth2wrap.NewMultiHTTP(time.Second, bmock.Address())
		require.NoError(t, err)

		cancel() // Cancel context before calling method.

		_, err = eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
		require.ErrorIs(t, err, context.Canceled)
	}
}

func TestBlockAttestations(t *testing.T) {
	atts := []*eth2p0.Attestation{
		testutil.RandomAttestation(),
		testutil.RandomAttestation(),
	}

	statusCode := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/eth/v1/beacon/blocks/head/attestations", r.URL.Path)
		b, err := json.Marshal(struct {
			Data []*eth2p0.Attestation
		}{
			Data: atts,
		})
		require.NoError(t, err)

		w.WriteHeader(statusCode)
		_, _ = w.Write(b)
	}))

	cl := eth2wrap.NewHTTPAdapterForT(t, srv.URL, time.Hour)
	resp, err := cl.BlockAttestations(context.Background(), "head")
	require.NoError(t, err)
	require.Equal(t, atts, resp)

	statusCode = http.StatusNotFound
	resp, err = cl.BlockAttestations(context.Background(), "head")
	require.NoError(t, err)
	require.Empty(t, resp)
}

// TestOneError tests the case where one of the servers returns errors.
func TestOneError(t *testing.T) {
	// Start an erroring server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ctx := context.Background()
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	addresses := []string{
		srv.URL,         // Invalid
		bmock.Address(), // Valid
	}

	eth2Cl, err := eth2wrap.NewMultiHTTP(time.Second, addresses...)
	require.NoError(t, err)

	eth2Resp, err := eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
	require.NoError(t, err)

	_, ok := eth2Resp.Data["SECONDS_PER_SLOT"].(time.Duration)
	require.True(t, ok)

	require.Equal(t, bmock.Address(), eth2Cl.Address())
}

// TestOneTimeout tests the case where one of the servers times out.
func TestOneTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Start an timeout server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-ctx.Done()
	}))
	defer srv.Close()
	defer cancel() // Cancel the context before stopping the server.

	bmock, err := beaconmock.New()
	require.NoError(t, err)

	addresses := []string{
		srv.URL,         // Invalid
		bmock.Address(), // Valid
	}

	eth2Cl, err := eth2wrap.NewMultiHTTP(time.Minute, addresses...)
	require.NoError(t, err)

	eth2Resp, err := eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
	require.NoError(t, err)

	_, ok := eth2Resp.Data["SECONDS_PER_SLOT"].(time.Duration)
	require.True(t, ok)

	require.Equal(t, bmock.Address(), eth2Cl.Address())
}

// TestOnlyTimeout tests the case where only one server is available and it is timing out.
func TestOnlyTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Start a timeout server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-ctx.Done()
	}))
	defer srv.Close()
	defer cancel() // Cancel the context before stopping the server.

	eth2Cl, err := eth2wrap.NewMultiHTTP(time.Minute, srv.URL)
	require.NoError(t, err)

	// Start goroutine that is blocking trying to create the client.
	go func() {
		_, _ = eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
		if ctx.Err() != nil {
			return
		}
		require.Fail(t, "Expect this only to return after main ctx cancelled")
	}()

	// testCtxCancel tests that no concurrent calls block if the user cancels the context.
	testCtxCancel := func(t *testing.T, timeout time.Duration) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		_, err := eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
		assert.Error(t, err)
	}

	// Start 10 concurrent goroutines that call the method.
	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			testCtxCancel(t, time.Millisecond*10)
			wg.Done()
		}()
	}
	wg.Wait()
}

func TestLazy(t *testing.T) {
	ctx := context.Background()

	bmock, err := beaconmock.New()
	require.NoError(t, err)

	target, err := url.Parse(bmock.Address())
	require.NoError(t, err)

	// Start two proxys that we can enable/disable.
	var enabled1, enabled2 atomic.Bool
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !enabled1.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		httputil.NewSingleHostReverseProxy(target).ServeHTTP(w, r)
	}))
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !enabled2.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		httputil.NewSingleHostReverseProxy(target).ServeHTTP(w, r)
	}))

	eth2Cl, err := eth2wrap.NewMultiHTTP(time.Second, srv1.URL, srv2.URL)
	require.NoError(t, err)

	// Both proxies are disabled, so this should fail.
	_, err = eth2Cl.NodeSyncing(ctx, nil)
	require.Error(t, err)
	require.Equal(t, "", eth2Cl.Address())

	enabled1.Store(true)

	// Proxy1 is enabled, so this should succeed.
	_, err = eth2Cl.NodeSyncing(ctx, &eth2api.NodeSyncingOpts{})
	require.NoError(t, err)
	require.Equal(t, srv1.URL, eth2Cl.Address())

	enabled1.Store(false)
	enabled2.Store(true)

	// Proxy2 is enabled, so this should succeed.
	for i := 0; i < 5; i++ { // Do multiple request to make Proxy2 the "best".
		_, err = eth2Cl.NodeSyncing(ctx, &eth2api.NodeSyncingOpts{})
		require.NoError(t, err)
	}

	require.Equal(t, srv2.URL, eth2Cl.Address())
}
