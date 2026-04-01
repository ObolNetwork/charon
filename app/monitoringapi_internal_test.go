// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/jonboulle/clockwork"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth1wrap"
	eth1wrapmocks "github.com/obolnetwork/charon/app/eth1wrap/mocks"
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
	tests := []struct {
		name                 string
		beaconAddrs          []string
		nodeVersionErr       error
		elVersion            string
		elErr                error
		wantNodeVersionCalls int
	}{
		{
			name:                 "success single beacon node with el",
			beaconAddrs:          []string{"http://beacon1:5052"},
			elVersion:            "Geth/v1.16.7-stable/linux-amd64/go1.22.0",
			wantNodeVersionCalls: 1,
		},
		{
			name:                 "success multiple beacon nodes with el",
			beaconAddrs:          []string{"http://beacon1:5052", "http://beacon2:5052"},
			elVersion:            "Geth/v1.16.7-stable/linux-amd64/go1.22.0",
			wantNodeVersionCalls: 2,
		},
		{
			name:                 "beacon node version error skips that node",
			beaconAddrs:          []string{"http://beacon1:5052"},
			nodeVersionErr:       errors.New("connection refused"),
			wantNodeVersionCalls: 1,
		},
		{
			name:        "no beacon nodes still queries el",
			beaconAddrs: []string{},
			elVersion:   "Geth/v1.16.7-stable/linux-amd64/go1.22.0",
		},
		{
			name:                 "el error no addr silently skipped",
			beaconAddrs:          []string{"http://beacon1:5052"},
			elErr:                eth1wrap.ErrNoExecutionEngineAddr,
			wantNodeVersionCalls: 1,
		},
		{
			name:                 "el generic error does not panic",
			beaconAddrs:          []string{"http://beacon1:5052"},
			elErr:                errors.New("rpc connection error"),
			wantNodeVersionCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			// done is closed by ClientVersion (always the last call in setNodeVersionAndID),
			// providing a happens-before guarantee that nodeVersionCalls is safe to read after.
			done := make(chan struct{})

			var nodeVersionCalls int

			bmock, err := beaconmock.New(t.Context())
			require.NoError(t, err)

			bmock.NodeVersionFunc = func(_ context.Context, _ *eth2api.NodeVersionOpts) (*eth2api.Response[string], error) {
				nodeVersionCalls++

				if tt.nodeVersionErr != nil {
					return nil, tt.nodeVersionErr
				}

				return &eth2api.Response[string]{Data: "Lighthouse/v5.3.0-aa022f4/x86_64-linux"}, nil
			}

			eth1Cl := eth1wrapmocks.NewEthClientRunner(t)
			eth1Cl.On("ClientVersion", mock.Anything).Run(func(_ mock.Arguments) {
				close(done)
			}).Return(tt.elVersion, tt.elErr).Once()

			clock := clockwork.NewFakeClock()

			consensusAndExecutionVersionMetric(ctx, bmock, tt.beaconAddrs, eth1Cl, clock)

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for ClientVersion call")
			}

			require.Equal(t, tt.wantNodeVersionCalls, nodeVersionCalls)
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
