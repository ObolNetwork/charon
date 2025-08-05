// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestStartChecker(t *testing.T) {
	pubkeys := []core.PubKey{testutil.RandomCorePubKey(t), testutil.RandomCorePubKey(t), testutil.RandomCorePubKey(t)}
	tests := []struct {
		name        string
		isSyncing   bool
		numPeers    int
		zeroBNPeers bool
		bnFarBehind bool
		absentPeers int
		seenPubkeys []core.PubKey
		noVAPICalls bool
		err         error
	}{
		{
			name:        "success",
			isSyncing:   false,
			numPeers:    5,
			absentPeers: 0,
			seenPubkeys: pubkeys,
		},
		{
			name:        "syncing",
			isSyncing:   true,
			numPeers:    5,
			absentPeers: 0,
			seenPubkeys: pubkeys,
			err:         errReadyBeaconNodeSyncing,
		},
		{
			name:        "zero BN peers",
			numPeers:    5,
			zeroBNPeers: true,
			seenPubkeys: pubkeys,
			err:         errReadyBeaconNodeZeroPeers,
		},
		{
			name:        "BN far behind",
			numPeers:    5,
			bnFarBehind: true,
			seenPubkeys: pubkeys,
			err:         errReadyBeaconNodeFarBehind,
		},
		{
			name:        "too few peers",
			isSyncing:   false,
			numPeers:    5,
			absentPeers: 3,
			seenPubkeys: pubkeys,
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
			name:        "vc missing validators",
			isSyncing:   false,
			numPeers:    4,
			absentPeers: 0,
			seenPubkeys: []core.PubKey{pubkeys[0]},
			err:         errReadyVCMissingVals,
		},
		{
			name:        "success",
			isSyncing:   false,
			numPeers:    4,
			absentPeers: 1,
			seenPubkeys: pubkeys,
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
			seenPubkeys := make(chan core.PubKey)
			vapiCalls := make(chan struct{})
			readyErrFunc := startReadyChecker(ctx, hosts[0], bmock, peers, clock,
				pubkeys, seenPubkeys, vapiCalls)

			for _, pubkey := range tt.seenPubkeys {
				seenPubkeys <- pubkey
			}

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
