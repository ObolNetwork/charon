// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"sync"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/jonboulle/clockwork"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth1wrap"
	eth1wrapmocks "github.com/obolnetwork/charon/app/eth1wrap/mocks"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestStartChecker(t *testing.T) {
	tests := []struct {
		name        string
		isSyncing   bool
		numPeers    int
		zeroBNPeers bool
		bnFarBehind bool
		absentPeers int
		noVAPICalls bool
		err         error
	}{
		{
			name:        "success",
			isSyncing:   false,
			numPeers:    5,
			absentPeers: 0,
		},
		{
			name:        "syncing",
			isSyncing:   true,
			numPeers:    5,
			absentPeers: 0,
			err:         errReadyBeaconNodeSyncing,
		},
		{
			name:        "zero BN peers",
			numPeers:    5,
			zeroBNPeers: true,
			err:         errReadyBeaconNodeZeroPeers,
		},
		{
			name:        "BN far behind",
			numPeers:    5,
			bnFarBehind: true,
			err:         errReadyBeaconNodeFarBehind,
		},
		{
			name:        "too few peers",
			isSyncing:   false,
			numPeers:    5,
			absentPeers: 3,
			err:         errReadyInsufficientPeers,
		},
		{
			name:        "vc not connected",
			isSyncing:   false,
			numPeers:    4,
			absentPeers: 0,
			noVAPICalls: true,
			err:         errReadyVCNotConnected,
		},
		{
			name:        "success",
			isSyncing:   false,
			numPeers:    4,
			absentPeers: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			slotDuration := 12 * time.Second
			slotsPerEpoch := 32

			bmock, err := beaconmock.New(t.Context(), beaconmock.WithSlotDuration(slotDuration), beaconmock.WithSlotsPerEpoch(slotsPerEpoch))
			require.NoError(t, err)

			bmock.NodeSyncingFunc = func(ctx context.Context, opts *eth2api.NodeSyncingOpts) (*eth2v1.SyncState, error) {
				return &eth2v1.SyncState{IsSyncing: tt.isSyncing}, nil
			}

			if tt.bnFarBehind {
				bmock.NodeSyncingFunc = func(ctx context.Context, opts *eth2api.NodeSyncingOpts) (*eth2v1.SyncState, error) {
					return &eth2v1.SyncState{IsSyncing: tt.isSyncing, SyncDistance: bnFarBehindSlots + 10}, nil // 320+10=330 slots behind head
				}
			}

			if tt.zeroBNPeers {
				bmock.NodePeerCountFunc = func(ctx context.Context, _ *eth2api.NodePeerCountOpts) (*eth2v1.PeerCount, error) {
					return &eth2v1.PeerCount{Connected: 0}, nil
				}
			}

			var (
				peers     []peer.ID
				hosts     []host.Host
				hostsInfo []peer.AddrInfo
			)

			for range tt.numPeers {
				h := testutil.CreateHost(t, testutil.AvailableAddr(t))
				info := peer.AddrInfo{
					ID:    h.ID(),
					Addrs: h.Addrs(),
				}
				hostsInfo = append(hostsInfo, info)
				peers = append(peers, h.ID())
				hosts = append(hosts, h)
			}

			// connect first peer with other peers, excluding absent ones
			for i := tt.absentPeers + 1; i < tt.numPeers; i++ {
				err := hosts[0].Connect(ctx, hostsInfo[i])
				require.NoError(t, err)
			}

			clock := clockwork.NewFakeClock()
			vapiCalls := make(chan struct{})
			readyErrFunc := startReadyChecker(ctx, hosts[0], bmock, peers, clock, vapiCalls)

			if !tt.noVAPICalls {
				vapiCalls <- struct{}{}
			}

			// Advance clock for first tick.
			advanceClock(t, ctx, clock, slotDuration)

			// Advance clock for first epoch tick.
			advanceClock(t, ctx, clock, time.Duration(slotsPerEpoch)*slotDuration)

			waitFor := 1 * time.Second

			tickInterval := 1 * time.Millisecond
			if tt.err != nil {
				require.Eventually(t, func() bool {
					advanceClock(t, ctx, clock, slotDuration)

					err = readyErrFunc()
					if !errors.Is(err, tt.err) {
						t.Logf("Ignoring unexpected error, got=%v, want=%v", err, tt.err)
						return false
					}

					return true
				}, waitFor, tickInterval)
			} else {
				require.Eventually(t, func() bool {
					advanceClock(t, ctx, clock, slotDuration)
					return readyErrFunc() == nil
				}, waitFor, tickInterval)
			}
		})
	}
}

func TestConsensusAndExecutionVersionMetric(t *testing.T) {
	v2WithEL := func() (*eth2api.Response[*eth2v1.NodeVersionV2], error) {
		return &eth2api.Response[*eth2v1.NodeVersionV2]{
			Data: &eth2v1.NodeVersionV2{
				BeaconNode: &eth2v1.ClientVersion{
					Code: "LH", Name: "Lighthouse", Version: "v5.3.0", Commit: "0xaa022f4",
				},
				ExecutionClient: &eth2v1.ClientVersion{
					Code: "GE", Name: "Geth", Version: "v1.16.7", Commit: "0xdeadbeef",
				},
			},
		}, nil
	}
	v2WithDifferentEL := func() (*eth2api.Response[*eth2v1.NodeVersionV2], error) {
		return &eth2api.Response[*eth2v1.NodeVersionV2]{
			Data: &eth2v1.NodeVersionV2{
				BeaconNode: &eth2v1.ClientVersion{
					Code: "TK", Name: "teku", Version: "v25.9.3", Commit: "0xfeedface",
				},
				ExecutionClient: &eth2v1.ClientVersion{
					Code: "NM", Name: "Nethermind", Version: "v1.35.0", Commit: "0xcafebabe",
				},
			},
		}, nil
	}
	v2BNOnly := func() (*eth2api.Response[*eth2v1.NodeVersionV2], error) { //nolint:unparam // shared signature with v2Err
		return &eth2api.Response[*eth2v1.NodeVersionV2]{
			Data: &eth2v1.NodeVersionV2{
				BeaconNode: &eth2v1.ClientVersion{
					Code: "LH", Name: "Lighthouse", Version: "v5.3.0", Commit: "0xaa022f4",
				},
			},
		}, nil
	}
	v2Err := func() (*eth2api.Response[*eth2v1.NodeVersionV2], error) {
		return nil, errors.New("v2 not supported")
	}

	tests := []struct {
		name        string
		beaconAddrs []string
		// V2 response per beacon node addr (in order). If absent, defaults to v2BNOnly.
		v2Funcs        []func() (*eth2api.Response[*eth2v1.NodeVersionV2], error)
		nodeVersionErr error
		elVersion      string
		elErr          error
		wantV2Calls    int
		wantV1Calls    int
		wantElCall     bool
		// wantElGaugeLabels lists the EL version labels the gauge is expected to carry
		// after the iteration (one per BN reporting an EL via V2, or one for the eth1Cl
		// fallback). Empty means the gauge has no entries.
		wantElGaugeLabels []string
		// wantWarn asserts whether the "Failed to fetch execution engine version" warning
		// is logged during the iteration. When false, absence is asserted; when true, presence is.
		wantWarn bool
	}{
		{
			name:              "v2 supplies BN and EL skips eth1 client",
			beaconAddrs:       []string{"http://beacon1:5052"},
			v2Funcs:           []func() (*eth2api.Response[*eth2v1.NodeVersionV2], error){v2WithEL},
			wantV2Calls:       1,
			wantElCall:        false,
			wantElGaugeLabels: []string{"Geth/v1.16.7/0xdeadbeef"},
		},
		{
			name:              "v2 supplies BN only falls back to eth1 client for EL",
			beaconAddrs:       []string{"http://beacon1:5052"},
			v2Funcs:           []func() (*eth2api.Response[*eth2v1.NodeVersionV2], error){v2BNOnly},
			elVersion:         "Geth/v1.16.7-stable/linux-amd64/go1.22.0",
			wantV2Calls:       1,
			wantElCall:        true,
			wantElGaugeLabels: []string{"Geth/v1.16.7-stable/linux-amd64/go1.22.0"},
		},
		{
			name:              "v2 fails falls back to v1 and eth1 client",
			beaconAddrs:       []string{"http://beacon1:5052"},
			v2Funcs:           []func() (*eth2api.Response[*eth2v1.NodeVersionV2], error){v2Err},
			elVersion:         "Geth/v1.16.7-stable/linux-amd64/go1.22.0",
			wantV2Calls:       1,
			wantV1Calls:       1,
			wantElCall:        true,
			wantElGaugeLabels: []string{"Geth/v1.16.7-stable/linux-amd64/go1.22.0"},
		},
		{
			name:              "v2 and v1 both fail skip beacon node but still query EL",
			beaconAddrs:       []string{"http://beacon1:5052"},
			v2Funcs:           []func() (*eth2api.Response[*eth2v1.NodeVersionV2], error){v2Err},
			nodeVersionErr:    errors.New("connection refused"),
			elVersion:         "Geth/v1.16.7-stable/linux-amd64/go1.22.0",
			wantV2Calls:       1,
			wantV1Calls:       1,
			wantElCall:        true,
			wantElGaugeLabels: []string{"Geth/v1.16.7-stable/linux-amd64/go1.22.0"},
		},
		{
			name:              "multiple beacon nodes first v2 supplies EL second v2 does not",
			beaconAddrs:       []string{"http://beacon1:5052", "http://beacon2:5052"},
			v2Funcs:           []func() (*eth2api.Response[*eth2v1.NodeVersionV2], error){v2WithEL, v2BNOnly},
			wantV2Calls:       2,
			wantElCall:        false,
			wantElGaugeLabels: []string{"Geth/v1.16.7/0xdeadbeef"},
		},
		{
			name:        "multiple beacon nodes each supply distinct ELs via v2",
			beaconAddrs: []string{"http://beacon1:5052", "http://beacon2:5052"},
			v2Funcs:     []func() (*eth2api.Response[*eth2v1.NodeVersionV2], error){v2WithEL, v2WithDifferentEL},
			wantV2Calls: 2,
			wantElCall:  false,
			wantElGaugeLabels: []string{
				"Geth/v1.16.7/0xdeadbeef",
				"Nethermind/v1.35.0/0xcafebabe",
			},
		},
		{
			name:              "multiple beacon nodes mixed v2 v1 fallback",
			beaconAddrs:       []string{"http://beacon1:5052", "http://beacon2:5052"},
			v2Funcs:           []func() (*eth2api.Response[*eth2v1.NodeVersionV2], error){v2WithEL, v2Err},
			wantV2Calls:       2,
			wantV1Calls:       1,
			wantElCall:        false,
			wantElGaugeLabels: []string{"Geth/v1.16.7/0xdeadbeef"},
		},
		{
			name:              "no beacon nodes still queries el",
			beaconAddrs:       []string{},
			elVersion:         "Geth/v1.16.7-stable/linux-amd64/go1.22.0",
			wantElCall:        true,
			wantElGaugeLabels: []string{"Geth/v1.16.7-stable/linux-amd64/go1.22.0"},
		},
		{
			name:        "el ErrNoExecutionEngineAddr silently skipped",
			beaconAddrs: []string{"http://beacon1:5052"},
			v2Funcs:     []func() (*eth2api.Response[*eth2v1.NodeVersionV2], error){v2BNOnly},
			elErr:       eth1wrap.ErrNoExecutionEngineAddr,
			wantV2Calls: 1,
			wantElCall:  true,
		},
		{
			name:        "el ErrEthClientNotConnected silently skipped",
			beaconAddrs: []string{"http://beacon1:5052"},
			v2Funcs:     []func() (*eth2api.Response[*eth2v1.NodeVersionV2], error){v2BNOnly},
			elErr:       eth1wrap.ErrEthClientNotConnected,
			wantV2Calls: 1,
			wantElCall:  true,
		},
		{
			name:        "el context.Canceled silently skipped",
			beaconAddrs: []string{"http://beacon1:5052"},
			v2Funcs:     []func() (*eth2api.Response[*eth2v1.NodeVersionV2], error){v2BNOnly},
			elErr:       context.Canceled,
			wantV2Calls: 1,
			wantElCall:  true,
		},
		{
			name:        "el context.DeadlineExceeded silently skipped",
			beaconAddrs: []string{"http://beacon1:5052"},
			v2Funcs:     []func() (*eth2api.Response[*eth2v1.NodeVersionV2], error){v2BNOnly},
			elErr:       context.DeadlineExceeded,
			wantV2Calls: 1,
			wantElCall:  true,
		},
		{
			name:        "el generic error warns and does not panic",
			beaconAddrs: []string{"http://beacon1:5052"},
			v2Funcs:     []func() (*eth2api.Response[*eth2v1.NodeVersionV2], error){v2BNOnly},
			elErr:       errors.New("rpc connection error"),
			wantV2Calls: 1,
			wantElCall:  true,
			wantWarn:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			obsCore, obsLogs := observer.New(zapcore.DebugLevel)
			ctx = log.WithLogger(ctx, zap.New(obsCore))

			var (
				mu          sync.Mutex
				v1Calls     int
				v2Calls     int
				elCalls     int
				v2CallIndex int
			)

			wantElCalls := 0
			if tt.wantElCall {
				wantElCalls = 1
			}

			bmock, err := beaconmock.New(t.Context())
			require.NoError(t, err)

			bmock.NodeVersionV2Func = func(_ context.Context, _ *eth2api.NodeVersionV2Opts) (*eth2api.Response[*eth2v1.NodeVersionV2], error) {
				mu.Lock()
				idx := v2CallIndex
				v2CallIndex++
				v2Calls++
				mu.Unlock()

				if idx < len(tt.v2Funcs) {
					return tt.v2Funcs[idx]()
				}

				return v2BNOnly()
			}

			bmock.NodeVersionFunc = func(_ context.Context, _ *eth2api.NodeVersionOpts) (*eth2api.Response[string], error) {
				mu.Lock()
				v1Calls++
				mu.Unlock()

				if tt.nodeVersionErr != nil {
					return nil, tt.nodeVersionErr
				}

				return &eth2api.Response[string]{Data: "Lighthouse/v5.3.0-aa022f4/x86_64-linux"}, nil
			}

			// Always allow eth1Cl.ClientVersion (Maybe) so unexpected calls don't panic;
			// the test asserts the exact call count via our own counter under mu.
			eth1Cl := eth1wrapmocks.NewEthClientRunner(t)
			eth1Cl.On("ClientVersion", mock.Anything).Run(func(_ mock.Arguments) {
				mu.Lock()
				elCalls++
				mu.Unlock()
			}).Return(tt.elVersion, tt.elErr).Maybe()

			clock := clockwork.NewFakeClock()

			consensusAndExecutionVersionMetric(ctx, bmock, tt.beaconAddrs, eth1Cl, clock)

			// Wait until the iteration has both made the expected mock calls AND populated
			// the gauge. The mock counter is incremented inside the mock call, but the gauge
			// Set happens later in the calling goroutine, so polling only the counters can
			// race ahead of the gauge write.
			require.Eventually(t, func() bool {
				mu.Lock()
				countsMatch := v2Calls == tt.wantV2Calls && v1Calls == tt.wantV1Calls && elCalls == wantElCalls
				mu.Unlock()

				if !countsMatch {
					return false
				}

				for _, label := range tt.wantElGaugeLabels {
					if promtestutil.ToFloat64(executionEngineVersionGauge.WithLabelValues(label)) != 1.0 {
						return false
					}
				}

				return true
			}, time.Second, 5*time.Millisecond, "timed out waiting for expected call counts and gauge labels")

			for _, label := range tt.wantElGaugeLabels {
				require.InDelta(t, 1.0,
					promtestutil.ToFloat64(executionEngineVersionGauge.WithLabelValues(label)),
					0.0, "EL gauge missing label %q", label)
			}

			hasWarn := func() bool {
				for _, e := range obsLogs.FilterMessageSnippet("Failed to fetch execution engine version").All() {
					if e.Level == zapcore.WarnLevel {
						return true
					}
				}

				return false
			}

			if tt.wantWarn {
				require.Eventually(t, hasWarn, time.Second, 5*time.Millisecond,
					"expected EL version warning at WARN level, got logs: %v", obsLogs.All())
			} else {
				require.Never(t, hasWarn, 100*time.Millisecond, 10*time.Millisecond,
					"expected no EL version warning, got logs: %v", obsLogs.All())
			}
		})
	}
}

func advanceClock(t *testing.T, ctx context.Context, clock *clockwork.FakeClock, duration time.Duration) {
	t.Helper()

	numTickers := 2

	// We wrap the Advance() calls with blockers to make sure that the ticker
	// can go to sleep and produce ticks without time passing in parallel.
	err := clock.BlockUntilContext(ctx, numTickers)
	require.NoError(t, err)
	clock.Advance(duration)
	err = clock.BlockUntilContext(ctx, numTickers)
	require.NoError(t, err)
}
