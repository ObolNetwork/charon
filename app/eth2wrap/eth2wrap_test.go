// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
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
	"github.com/obolnetwork/charon/eth2util"
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

	resp, err := eth2Cl.NodeSyncing(context.Background(), nil)
	require.NoError(t, err)
	require.False(t, resp.Data.IsSyncing)
}

func TestErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("network dial error", func(t *testing.T) {
		cl, err := eth2wrap.NewMultiHTTP(time.Hour, [4]byte{}, "localhost:22222")
		require.NoError(t, err)

		_, err = cl.SlotsPerEpoch(ctx)
		log.Error(ctx, "See this error log for fields", err)
		require.Error(t, err)
		require.ErrorContains(t, err, "beacon api slots_per_epoch: client is not active")
	})

	// Test http server that just hangs until request cancelled
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))

	t.Run("http timeout", func(t *testing.T) {
		cl, err := eth2wrap.NewMultiHTTP(time.Millisecond, [4]byte{}, srv.URL)
		require.NoError(t, err)

		_, err = cl.SlotsPerEpoch(ctx)
		log.Error(ctx, "See this error log for fields", err)
		require.Error(t, err)
		require.ErrorContains(t, err, "beacon api slots_per_epoch: client is not active")
	})

	t.Run("caller cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(ctx)
		cancel()

		cl, err := eth2wrap.NewMultiHTTP(time.Millisecond, [4]byte{}, srv.URL)
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
				Endpoint:   "/eth/v3/beacon/blocks/" + blockID,
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
	for range 10 {
		ctx, cancel := context.WithCancel(context.Background())

		bmock, err := beaconmock.New()
		require.NoError(t, err)
		eth2Cl, err := eth2wrap.NewMultiHTTP(time.Second, [4]byte{}, bmock.Address())
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

	eth2Cl, err := eth2wrap.NewMultiHTTP(time.Second, [4]byte{}, addresses...)
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

	eth2Cl, err := eth2wrap.NewMultiHTTP(time.Minute, [4]byte{}, addresses...)
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

	eth2Cl, err := eth2wrap.NewMultiHTTP(time.Minute, [4]byte{}, srv.URL)
	require.NoError(t, err)

	// Start goroutine that is blocking trying to create the client.
	go func() {
		_, _ = eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
		if ctx.Err() != nil {
			return
		}
		require.Fail(t, "Expect this only to return after main ctx cancelled") //nolint:testifylint // TODO: find a way to do that outside of go routine
	}()

	// Allow the above goroutine to block on the .Spec() call.
	time.Sleep(10 * time.Millisecond)

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
	for range n {
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

	target := testutil.MustParseURL(t, bmock.Address())

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

	eth2Cl, err := eth2wrap.NewMultiHTTP(time.Second, [4]byte{}, srv1.URL, srv2.URL)
	require.NoError(t, err)

	// Both proxies are disabled, so this should fail.
	_, err = eth2Cl.NodeSyncing(ctx, nil)
	require.Error(t, err)

	enabled1.Store(true)

	// Proxy1 is enabled, so this should succeed.
	_, err = eth2Cl.NodeSyncing(ctx, &eth2api.NodeSyncingOpts{})
	require.NoError(t, err)
	require.Equal(t, srv1.URL, eth2Cl.Address())

	enabled1.Store(false)
	enabled2.Store(true)

	// Proxy2 is enabled, so this should succeed.
	for range 5 { // Do multiple request to make Proxy2 the "best".
		_, err = eth2Cl.NodeSyncing(ctx, &eth2api.NodeSyncingOpts{})
		require.NoError(t, err)
	}

	require.Equal(t, srv2.URL, eth2Cl.Address())
}

func TestLazyDomain(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		expErr string
		expRes string
	}{
		{
			name:   "mainnet fork",
			in:     eth2util.Mainnet.GenesisForkVersionHex[2:],
			expRes: "040000008c6ebbceb21209e6af5ab7db4a3027998c412c0eb0e15fbc1ee75617",
		},
		{
			name:   "goerli fork",
			in:     eth2util.Goerli.GenesisForkVersionHex[2:],
			expRes: "04000000628941ef21d1fe8c7134720add10bb91e3b02c007e0046d2472c6695",
		},
		{
			name:   "gnosis fork",
			in:     eth2util.Gnosis.GenesisForkVersionHex[2:],
			expRes: "04000000398beb768264920602d7d79f88da05cac0550ae4108753fd846408b5",
		},
		{
			name:   "sepolia fork",
			in:     eth2util.Sepolia.GenesisForkVersionHex[2:],
			expRes: "040000007191d9b3c210dbffc7810b6ccb436c1b3897b6772452924b20f6f5f2",
		},
		{
			name:   "holesky fork",
			in:     eth2util.Holesky.GenesisForkVersionHex[2:],
			expRes: "040000002b3e2c2d17a0d820f3099580a72d1bc743b17616ff7851f32aa303ad",
		},
		{
			name:   "unknown fork",
			in:     "00000001",
			expErr: "beacon api domain: get domain: compute domain: invalid fork hash: no capella fork for specified fork",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()

			bmock, err := beaconmock.New()
			require.NoError(t, err)

			target := testutil.MustParseURL(t, bmock.Address())

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				httputil.NewSingleHostReverseProxy(target).ServeHTTP(w, r)
			}))

			forkVersionHex, err := hex.DecodeString(test.in)
			require.NoError(t, err)
			eth2Cl, err := eth2wrap.NewMultiHTTP(time.Second, [4]byte(forkVersionHex), srv.URL)
			require.NoError(t, err)

			voluntaryExitDomain := eth2p0.DomainType{0x04, 0x00, 0x00, 0x00}
			f, err := eth2Cl.Domain(ctx, voluntaryExitDomain, testutil.RandomEpoch())

			if test.expErr != "" {
				require.ErrorContains(t, err, test.expErr)
			} else {
				require.Equal(t, test.expRes, hex.EncodeToString(f[:]))
			}
		})
	}
}
