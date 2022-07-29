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
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestStartChecker(t *testing.T) {
	tests := []struct {
		name        string
		isSyncing   bool
		numPeers    int
		absentPeers int
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
			err:         errReadySyncing,
		},
		{
			name:        "peer ping failing",
			isSyncing:   false,
			numPeers:    5,
			absentPeers: 3,
			err:         errReadyPingFailing,
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

			// connect each host with its peers
			for i := 0; i < tt.numPeers; i++ {
				for k := 0; k < tt.numPeers-tt.absentPeers; k++ {
					if i == k {
						continue
					}
					hosts[i].Peerstore().AddAddrs(hostsInfo[k].ID, hostsInfo[k].Addrs, peerstore.PermanentAddrTTL)
				}
			}

			clock := clockwork.NewFakeClock()
			readyErrFunc := startReadyChecker(ctx, hosts[0], bmock, peers, clock)

			// We wrap the Advance() calls with blockers to make sure that the ticker
			// can go to sleep and produce ticks without time passing in parallel.
			clock.BlockUntil(1)
			clock.Advance(15 * time.Second)
			clock.BlockUntil(1)

			if tt.err != nil {
				require.Eventually(t, func() bool {
					err = readyErrFunc()
					if err != nil {
						require.EqualError(t, err, tt.err.Error())
						return true
					}

					return false
				}, 100*time.Millisecond, time.Millisecond)
			} else {
				require.Eventually(t, func() bool {
					err = readyErrFunc()
					if err == nil {
						return true
					}

					return false
				}, 100*time.Millisecond, time.Millisecond)
			}
		})
	}
}
