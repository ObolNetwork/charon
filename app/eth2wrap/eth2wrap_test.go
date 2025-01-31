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
	eth2e "github.com/attestantio/go-eth2-client/spec/electra"
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

			eth2Cl, err := eth2wrap.Instrument([]eth2wrap.Client{cl1, cl2}, nil)
			require.NoError(t, err)

			go test.handle(cl1Resp, cl2Resp, cancel)

			resp, err := eth2Cl.SlotsPerEpoch(ctx)
			require.ErrorIs(t, err, test.expErr)
			require.Equal(t, test.expRes, resp)
		})
	}
}

func TestFallback(t *testing.T) {
	returnValue := uint64(42)
	closedErr := errors.New("error")

	tests := []struct {
		name         string
		primaryErrs  []error
		fallbackErrs []error
	}{
		{
			name:         "primary success - no fallback called",
			primaryErrs:  []error{nil, nil},
			fallbackErrs: []error{nil, nil},
		},
		{
			name:         "one primary success - no fallback called",
			primaryErrs:  []error{nil, closedErr},
			fallbackErrs: []error{nil, nil},
		},
		{
			name:         "all primary fail - fallback called",
			primaryErrs:  []error{closedErr, closedErr},
			fallbackErrs: []error{nil, nil},
		},
		{
			name:         "all primary fail - one fallback success",
			primaryErrs:  []error{closedErr, closedErr},
			fallbackErrs: []error{nil, closedErr},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calledMu sync.Mutex
			primaryCalled := make([]bool, len(tt.primaryErrs))
			fallbackCalled := make([]bool, len(tt.fallbackErrs))

			// Track if all primaries fail to check if fallback must be called
			allPrimariesFail := true
			// Create primary clients
			primaryClients := make([]eth2wrap.Client, len(tt.primaryErrs))
			for i, primaryErr := range tt.primaryErrs {
				if primaryErr == nil {
					allPrimariesFail = false
				}
				cl, err := beaconmock.New()
				require.NoError(t, err)

				cl.SlotsPerEpochFunc = func(context.Context) (uint64, error) {
					calledMu.Lock()
					primaryCalled[i] = true
					calledMu.Unlock()

					return returnValue, primaryErr
				}
				primaryClients[i] = cl
			}

			// Create fallback client
			fallbackClients := make([]eth2wrap.Client, len(tt.fallbackErrs))
			for i, fallbackErr := range tt.fallbackErrs {
				cl, err := beaconmock.New()
				require.NoError(t, err)

				cl.SlotsPerEpochFunc = func(context.Context) (uint64, error) {
					calledMu.Lock()
					fallbackCalled[i] = true
					calledMu.Unlock()

					return returnValue, fallbackErr
				}
				fallbackClients[i] = cl
			}

			eth2Cl, err := eth2wrap.Instrument(primaryClients, fallbackClients)
			require.NoError(t, err)
			res, err := eth2Cl.SlotsPerEpoch(context.Background())
			require.NoError(t, err)
			require.Equal(t, returnValue, res)

			calledMu.Lock()
			defer calledMu.Unlock()

			// Helper function to check if at least one client was called
			atLeastOneCalled := func(called []bool) bool {
				for _, c := range called {
					if c {
						return true
					}
				}
				return false
			}

			// Only possible to check if all primaries are called if they all fail because
			// otherwise one could return sooner without the other even being called.
			if allPrimariesFail {
				for i, called := range primaryCalled {
					require.True(t, called, "primary client %d was not called", i)
				}
				require.True(t, atLeastOneCalled(fallbackCalled), "at least one fallback client should have been called")

			} else {
				require.True(t, atLeastOneCalled(primaryCalled), "at least one primary client should have been called")
			}
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

	eth2Cl, err := eth2wrap.Instrument([]eth2wrap.Client{cl1, cl2}, nil)
	require.NoError(t, err)

	resp, err := eth2Cl.NodeSyncing(context.Background(), nil)
	require.NoError(t, err)
	require.False(t, resp.Data.IsSyncing)
}

func TestErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("network dial error", func(t *testing.T) {
		cl, err := eth2wrap.NewMultiHTTP(time.Hour, [4]byte{}, nil, []string{"localhost:22222"}, nil)
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
		cl, err := eth2wrap.NewMultiHTTP(time.Millisecond, [4]byte{}, nil, []string{srv.URL}, nil)
		require.NoError(t, err)

		_, err = cl.SlotsPerEpoch(ctx)
		log.Error(ctx, "See this error log for fields", err)
		require.Error(t, err)
		require.ErrorContains(t, err, "beacon api slots_per_epoch: client is not active")
	})

	t.Run("caller cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(ctx)
		cancel()

		cl, err := eth2wrap.NewMultiHTTP(time.Millisecond, [4]byte{}, nil, []string{srv.URL}, nil)
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
		eth2Cl, err := eth2wrap.Instrument([]eth2wrap.Client{bmock}, nil)
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

		eth2Cl, err := eth2wrap.Instrument([]eth2wrap.Client{bmock}, nil)
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
		eth2Cl, err := eth2wrap.NewMultiHTTP(time.Second, [4]byte{}, nil, []string{bmock.Address()}, nil)
		require.NoError(t, err)

		cancel() // Cancel context before calling method.

		_, err = eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
		require.ErrorIs(t, err, context.Canceled)
	}
}

func TestBlockAttestationsV2(t *testing.T) {
	phase0Att1 := testutil.RandomPhase0Attestation()
	phase0Att2 := testutil.RandomPhase0Attestation()
	electraAtt1 := testutil.RandomElectraAttestation()
	electraAtt2 := testutil.RandomElectraAttestation()

	tests := []struct {
		version          string
		attestations     []*eth2spec.VersionedAttestation
		serverJSONStruct any
		expErr           string
	}{
		{
			version: "electra",
			attestations: []*eth2spec.VersionedAttestation{
				{Version: eth2spec.DataVersionElectra, Electra: electraAtt1},
				{Version: eth2spec.DataVersionElectra, Electra: electraAtt2},
			},
			serverJSONStruct: struct{ Data []*eth2e.Attestation }{Data: []*eth2e.Attestation{electraAtt1, electraAtt2}},
			expErr:           "",
		},
		{
			version: "deneb",
			attestations: []*eth2spec.VersionedAttestation{
				{Version: eth2spec.DataVersionDeneb, Deneb: phase0Att1},
				{Version: eth2spec.DataVersionDeneb, Deneb: phase0Att2},
			},
			serverJSONStruct: struct{ Data []*eth2p0.Attestation }{Data: []*eth2p0.Attestation{phase0Att1, phase0Att2}},
			expErr:           "",
		},
		{
			version: "capella",
			attestations: []*eth2spec.VersionedAttestation{
				{Version: eth2spec.DataVersionCapella, Capella: phase0Att1},
				{Version: eth2spec.DataVersionCapella, Capella: phase0Att2},
			},
			serverJSONStruct: struct{ Data []*eth2p0.Attestation }{Data: []*eth2p0.Attestation{phase0Att1, phase0Att2}},
			expErr:           "",
		},
		{
			version: "bellatrix",
			attestations: []*eth2spec.VersionedAttestation{
				{Version: eth2spec.DataVersionBellatrix, Bellatrix: phase0Att1},
				{Version: eth2spec.DataVersionBellatrix, Bellatrix: phase0Att2},
			},
			serverJSONStruct: struct{ Data []*eth2p0.Attestation }{Data: []*eth2p0.Attestation{phase0Att1, phase0Att2}},
			expErr:           "",
		},
		{
			version: "altair",
			attestations: []*eth2spec.VersionedAttestation{
				{Version: eth2spec.DataVersionAltair, Altair: phase0Att1},
				{Version: eth2spec.DataVersionAltair, Altair: phase0Att2},
			},
			serverJSONStruct: struct{ Data []*eth2p0.Attestation }{Data: []*eth2p0.Attestation{phase0Att1, phase0Att2}},
			expErr:           "",
		},
		{
			version: "phase0",
			attestations: []*eth2spec.VersionedAttestation{
				{Version: eth2spec.DataVersionPhase0, Phase0: phase0Att1},
				{Version: eth2spec.DataVersionPhase0, Phase0: phase0Att2},
			},
			serverJSONStruct: struct{ Data []*eth2p0.Attestation }{Data: []*eth2p0.Attestation{phase0Att1, phase0Att2}},
			expErr:           "",
		},
		{
			version:          "unknown version",
			attestations:     nil,
			serverJSONStruct: struct{ Data []*eth2p0.Attestation }{Data: []*eth2p0.Attestation{phase0Att1, phase0Att2}},
			expErr:           "failed to get consensus version",
		},
	}
	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			statusCode := http.StatusOK
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "/eth/v2/beacon/blocks/head/attestations", r.URL.Path)
				b, err := json.Marshal(test.serverJSONStruct)
				require.NoError(t, err)

				w.Header().Add("Eth-Consensus-Version", test.version)
				w.WriteHeader(statusCode)
				_, _ = w.Write(b)
			}))

			cl := eth2wrap.NewHTTPAdapterForT(t, srv.URL, nil, time.Hour)
			resp, err := cl.BlockAttestationsV2(context.Background(), "head")
			if test.expErr != "" {
				require.ErrorContains(t, err, test.expErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, test.attestations, resp)

			statusCode = http.StatusNotFound
			resp, err = cl.BlockAttestationsV2(context.Background(), "head")
			require.NoError(t, err)
			require.Empty(t, resp)
		})
	}
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

	eth2Cl, err := eth2wrap.NewMultiHTTP(time.Second, [4]byte{}, nil, addresses, nil)
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

	eth2Cl, err := eth2wrap.NewMultiHTTP(time.Minute, [4]byte{}, nil, addresses, nil)
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

	eth2Cl, err := eth2wrap.NewMultiHTTP(time.Minute, [4]byte{}, nil, []string{srv.URL}, nil)
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

	eth2Cl, err := eth2wrap.NewMultiHTTP(time.Second, [4]byte{}, nil, []string{srv1.URL, srv2.URL}, nil)
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
			expRes: "04000000a39ec13dbafa3a331644f8d3a1513e57898fab998fec78f5ada4b8b0",
		},
		{
			name:   "goerli fork",
			in:     eth2util.Goerli.GenesisForkVersionHex[2:],
			expRes: "04000000f1e25bda59286379f9a2b3ffeb090d650a4db4cfd089e1cc72388a33",
		},
		{
			name:   "gnosis fork",
			in:     eth2util.Gnosis.GenesisForkVersionHex[2:],
			expRes: "040000007c97bfcba5d28a3cdef2ab010944574e387f4b3c7963c215eed87f32",
		},
		{
			name:   "sepolia fork",
			in:     eth2util.Sepolia.GenesisForkVersionHex[2:],
			expRes: "0400000005b54270938f654bd779212d3be2a63f806a4f58794d455393d8dad8",
		},
		{
			name:   "holesky fork",
			in:     eth2util.Holesky.GenesisForkVersionHex[2:],
			expRes: "0400000017e2dad36f1d3595152042a9ad23430197557e2e7e82bc7f7fc72972",
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
			eth2Cl, err := eth2wrap.NewMultiHTTP(time.Second, [4]byte(forkVersionHex), nil, []string{srv.URL}, nil)
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
