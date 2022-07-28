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

func TestStartCheckerSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bmock, err := beaconmock.New()
	require.NoError(t, err)

	const numNodes = 3
	var (
		peers     []peer.ID
		hosts     []host.Host
		hostsInfo []peer.AddrInfo
	)

	for i := 0; i < numNodes; i++ {
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
	for i := 0; i < numNodes; i++ {
		for k := 0; k < numNodes; k++ {
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

	require.NoError(t, readyErrFunc())
}

func TestStartCheckerSyncing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bmock, err := beaconmock.New()
	require.NoError(t, err)

	bmock.NodeSyncingFunc = func(ctx context.Context) (*eth2v1.SyncState, error) {
		return &eth2v1.SyncState{IsSyncing: true}, nil
	}

	const numNodes = 3
	var (
		peers     []peer.ID
		hosts     []host.Host
		hostsInfo []peer.AddrInfo
	)

	for i := 0; i < numNodes; i++ {
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
	for i := 0; i < numNodes; i++ {
		for k := 0; k < numNodes; k++ {
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

	// Infinite loop required since mutexes are non-deterministic.
	for {
		err := readyErrFunc()
		if err != nil {
			require.EqualError(t, err, "beacon node not synced")
			break
		}
	}
}

func TestStartCheckerPingFail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bmock, err := beaconmock.New()
	require.NoError(t, err)

	bmock.NodeSyncingFunc = func(ctx context.Context) (*eth2v1.SyncState, error) {
		return &eth2v1.SyncState{IsSyncing: false}, nil
	}

	const numNodes = 5
	var (
		peers     []peer.ID
		hosts     []host.Host
		hostsInfo []peer.AddrInfo
	)

	for i := 0; i < numNodes; i++ {
		h := testutil.CreateHost(t, testutil.AvailableAddr(t))
		info := peer.AddrInfo{
			ID:    h.ID(),
			Addrs: h.Addrs(),
		}
		hostsInfo = append(hostsInfo, info)
		peers = append(peers, h.ID())
		hosts = append(hosts, h)
	}

	// Connect each host with its peers except 3 peers so that quorum number of peers cannot connect.
	for i := 0; i < numNodes; i++ {
		for k := 0; k < numNodes-3; k++ {
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

	// Infinite loop required since mutexes are non-deterministic.
	for {
		err := readyErrFunc()
		if err != nil {
			require.EqualError(t, err, "couldn't ping all peers")
			break
		}
	}
}
