// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package leadercast_test

import (
	"bytes"
	"context"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/leadercast"
	"github.com/obolnetwork/charon/testutil"
)

func TestMemTransport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	trFunc := leadercast.NewMemTransportFunc(ctx)

	const (
		notZero = 99
		n       = 3
		slots   = 3
		commLen = 8
	)

	// generate random public keys for each peer
	pubkeysByIdx := map[int]core.PubKey{}
	for i := 0; i < n; i++ {
		pubkeysByIdx[i] = testutil.RandomCorePubKey(t)
	}

	// leadercast in memory transport consensus for peers for each slot
	var casts []*leadercast.LeaderCast
	resolved := make(chan core.UnsignedDataSet, slots*n) // actual broadcasted data
	for i := 0; i < n; i++ {
		c := leadercast.New(trFunc(), i, n)
		// function to catch broadcasted data
		c.Subscribe(func(ctx context.Context, duty core.Duty, set core.UnsignedDataSet) error {
			resolved <- set
			return nil
		})
		casts = append(casts, c)

		go func() {
			require.NoError(t, c.Run(ctx))
		}()
	}

	// propose attestation for each slot
	var expected []core.UnsignedDataSet
	for i := 0; i < slots; i++ {
		duty := core.Duty{Slot: int64(i)}
		data := core.UnsignedDataSet{}
		for j := 0; j < n; j++ {
			unsignedData, err := core.EncodeAttesterUnsignedData(&core.AttestationData{
				Data: *testutil.RandomAttestationData(),
				Duty: eth2v1.AttesterDuty{
					CommitteeLength:         commLen,
					ValidatorCommitteeIndex: uint64(j),
					CommitteesAtSlot:        notZero,
				},
			})
			require.NoError(t, err)

			data[pubkeysByIdx[j]] = unsignedData
		}

		expected = append(expected, data)

		for j := 0; j < n; j++ {
			go func(node int) {
				err := casts[node].Propose(ctx, duty, data)
				require.NoError(t, err)
			}(j)
		}
	}

	var actual []core.UnsignedDataSet
	for i := 0; i < slots*n; i++ {
		actual = append(actual, <-resolved)
	}

	// asserts that actual and expected are equal
	for _, expect := range expected {
		var count int
		for _, resolved := range actual {
			for j := 0; j < n; j++ {
				a := resolved[pubkeysByIdx[j]]
				b := expect[pubkeysByIdx[j]]
				// increase count if all the bytes are equal in between expected and actual data
				if bytes.Equal(a, b) {
					count++
				}
			}
		}
		// assert total number of bytes to be equal in between expected and actual data
		require.Equal(t, n*slots, count, expect)
	}
}

func TestP2PTransport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const (
		notZero = 99
		n       = 3
		slots   = 3
		commLen = 8
	)

	var (
		peers     []peer.ID
		hosts     []host.Host
		hostsInfo []peer.AddrInfo
	)

	// create hosts
	for i := 0; i < n; i++ {
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
	for i := 0; i < n; i++ {
		for k := 0; k < n; k++ {
			if i == k {
				continue
			}
			hosts[i].Peerstore().AddAddrs(hostsInfo[k].ID, hostsInfo[k].Addrs, peerstore.PermanentAddrTTL)
		}
	}

	// generate random public keys for each peer
	pubkeysByIdx := map[int]core.PubKey{}
	for i := 0; i < n; i++ {
		pubkeysByIdx[i] = testutil.RandomCorePubKey(t)
	}

	// leadercast P2P transport consensus for peers for each slot
	var casts []*leadercast.LeaderCast
	resolved := make(chan core.UnsignedDataSet, slots*n)
	for i := 0; i < n; i++ {
		p2pTr := leadercast.NewP2PTransport(hosts[i], i, peers)
		c := leadercast.New(p2pTr, i, n)
		c.Subscribe(func(ctx context.Context, duty core.Duty, set core.UnsignedDataSet) error {
			resolved <- set
			return nil
		})
		casts = append(casts, c)

		go func() {
			require.NoError(t, c.Run(ctx))
		}()
	}

	// propose attestation for each slot
	var expected []core.UnsignedDataSet
	for i := 0; i < slots; i++ {
		duty := core.Duty{Slot: int64(i)}
		data := core.UnsignedDataSet{}
		for j := 0; j < n; j++ {
			unsignedData, err := core.EncodeAttesterUnsignedData(&core.AttestationData{
				Data: *testutil.RandomAttestationData(),
				Duty: eth2v1.AttesterDuty{
					CommitteeLength:         commLen,
					ValidatorCommitteeIndex: uint64(j),
					CommitteesAtSlot:        notZero,
				},
			})
			require.NoError(t, err)

			data[pubkeysByIdx[j]] = unsignedData
		}

		expected = append(expected, data)

		for j := 0; j < n; j++ {
			go func(node int) {
				err := casts[node].Propose(ctx, duty, data)
				require.NoError(t, err)
			}(j)
		}
	}

	var actual []core.UnsignedDataSet
	for i := 0; i < slots*n; i++ {
		actual = append(actual, <-resolved)
	}

	// asserts that actual and expected are equal
	for _, expect := range expected {
		var count int
		for _, resolved := range actual {
			for j := 0; j < n; j++ {
				a := resolved[pubkeysByIdx[j]]
				b := expect[pubkeysByIdx[j]]
				// increase count if all the bytes are equal in between expected and actual data
				if bytes.Equal(a, b) {
					count++
				}
			}
		}
		// assert total number of bytes to be equal in between expected and actual data
		require.Equal(t, n*slots, count, expect)
	}
}
