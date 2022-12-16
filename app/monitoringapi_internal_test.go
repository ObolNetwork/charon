// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package app

import (
	"context"
	"testing"
	"time"

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
		absentPeers int
		seenPubkeys []core.PubKey
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
			name:        "too few peers",
			isSyncing:   false,
			numPeers:    5,
			absentPeers: 3,
			seenPubkeys: pubkeys,
			err:         errReadyInsufficientPeers,
		},
		// {
		//	name:        "vc not configured",
		//	isSyncing:   false,
		//	numPeers:    4,
		//	absentPeers: 0,
		//	err:         errReadyVCNotConfigured,
		// },
		// {
		//	name:        "vc missing some validators",
		//	isSyncing:   false,
		//	numPeers:    4,
		//	absentPeers: 0,
		//	seenPubkeys: []core.PubKey{pubkeys[0]},
		//	err:         errReadyVCMissingVals,
		// },
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
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			bmock, err := beaconmock.New()
			require.NoError(t, err)

			bmock.NodeSyncingFunc = func(ctx context.Context) (*eth2v1.SyncState, error) {
				return &eth2v1.SyncState{IsSyncing: tt.isSyncing}, nil
			}

			var (
				peers     []peer.ID
				hosts     []host.Host
				hostsInfo []peer.AddrInfo
			)

			for i := 0; i < tt.numPeers; i++ {
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
			readyErrFunc := startReadyChecker(ctx, hosts[0], bmock, peers, clock, pubkeys, seenPubkeys)

			for _, pubkey := range tt.seenPubkeys {
				seenPubkeys <- pubkey
			}

			// Advance clock for first tick.
			advanceClock(clock, 10*time.Second, 2)

			// Advance clock for first epoch tick.
			advanceClock(clock, 384*time.Second, 2)

			// Advance clock for last tick.
			advanceClock(clock, 10*time.Second, 2)

			if tt.err != nil {
				require.Eventually(t, func() bool {
					err = readyErrFunc()
					if !errors.Is(err, errReadyUninitialised) {
						require.EqualError(t, err, tt.err.Error())
						return true
					}

					return false
				}, time.Second, 100*time.Millisecond)
			} else {
				require.Eventually(t, func() bool {
					return readyErrFunc() == nil
				}, time.Second, 100*time.Millisecond)
			}
		})
	}
}

func advanceClock(clock clockwork.FakeClock, duration time.Duration, numTickers int) {
	// We wrap the Advance() calls with blockers to make sure that the ticker
	// can go to sleep and produce ticks without time passing in parallel.
	clock.BlockUntil(numTickers)
	clock.Advance(duration)
	clock.BlockUntil(numTickers)
}
