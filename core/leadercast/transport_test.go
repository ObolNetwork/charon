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
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
	noise "github.com/libp2p/go-libp2p-noise"
	"github.com/libp2p/go-tcp-transport"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/log"
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
		vIdxA   = 0
		vIdxB   = 1
		vIdxC   = 2
		slots   = 3
		commIdx = 123
		commLen = 8
	)

	pubkeysByIdx := map[eth2p0.ValidatorIndex]core.PubKey{
		vIdxA: testutil.RandomPubKey(t),
		vIdxB: testutil.RandomPubKey(t),
		vIdxC: testutil.RandomPubKey(t),
	}

	var casts []*leadercast.LeaderCast
	resolved := make(chan core.UnsignedDataSet, slots*n)
	for i := 0; i < n; i++ {
		c := leadercast.New(trFunc(), i, n)
		c.Subscribe(func(ctx context.Context, duty core.Duty, set core.UnsignedDataSet) error {
			resolved <- set
			return nil
		})
		casts = append(casts, c)

		go func() {
			require.NoError(t, c.Run(ctx))
		}()
	}

	var expected []core.UnsignedDataSet
	for i := 0; i < slots; i++ {
		duty := core.Duty{Slot: int64(i)}
		data := core.UnsignedDataSet{}
		for j := 0; j < n; j++ {
			unsignedData, err := core.EncodeAttesterUnsignedData(&core.AttestationData{
				Data: eth2p0.AttestationData{
					Slot:   eth2p0.Slot(i),
					Index:  commIdx,
					Source: &eth2p0.Checkpoint{},
					Target: &eth2p0.Checkpoint{},
				},
				Duty: eth2v1.AttesterDuty{
					CommitteeLength:         commLen,
					ValidatorCommitteeIndex: uint64(j),
					CommitteesAtSlot:        notZero,
				},
			})
			require.NoError(t, err)

			data[pubkeysByIdx[eth2p0.ValidatorIndex(j)]] = unsignedData
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

	for _, expect := range expected {
		var count int
		for _, resolved := range actual {
			for j := 0; j < n; j++ {
				a := resolved[pubkeysByIdx[eth2p0.ValidatorIndex(j)]]
				b := expect[pubkeysByIdx[eth2p0.ValidatorIndex(j)]]
				if bytes.Equal(a, b) {
					count++
				}
			}
		}
		require.Equal(t, n*slots, count, expect)
	}
}

func TestP2PTransport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const (
		notZero = 99
		n       = 3
		vIdxA   = 0
		vIdxB   = 1
		vIdxC   = 2
		slots   = 3
		commIdx = 123
		commLen = 8
	)

	portStart := 15000
	var (
		peers     []peer.ID
		hosts     []host.Host
		hostsInfo []peer.AddrInfo
	)

	// create hosts
	for i := 0; i < n; i++ {
		h := createHost(t, portStart)
		info := peer.AddrInfo{
			ID:    h.ID(),
			Addrs: h.Addrs(),
		}
		hostsInfo = append(hostsInfo, info)
		peers = append(peers, h.ID())
		hosts = append(hosts, h)
		portStart++
	}

	pubkeysByIdx := map[eth2p0.ValidatorIndex]core.PubKey{
		vIdxA: testutil.RandomPubKey(t),
		vIdxB: testutil.RandomPubKey(t),
		vIdxC: testutil.RandomPubKey(t),
	}

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

	var expected []core.UnsignedDataSet
	var wg sync.WaitGroup
	for i := 0; i < slots; i++ {
		duty := core.Duty{Slot: int64(i)}
		data := core.UnsignedDataSet{}
		for j := 0; j < n; j++ {
			unsignedData, err := core.EncodeAttesterUnsignedData(&core.AttestationData{
				Data: eth2p0.AttestationData{
					Slot:   eth2p0.Slot(i),
					Index:  commIdx,
					Source: &eth2p0.Checkpoint{},
					Target: &eth2p0.Checkpoint{},
				},
				Duty: eth2v1.AttesterDuty{
					CommitteeLength:         commLen,
					ValidatorCommitteeIndex: uint64(j),
					CommitteesAtSlot:        notZero,
				},
			})
			require.NoError(t, err)

			data[pubkeysByIdx[eth2p0.ValidatorIndex(j)]] = unsignedData
		}

		expected = append(expected, data)

		for j := 0; j < n; j++ {
			wg.Add(1)
			j := j
			go func(node int) {
				defer wg.Done()

				for k := 0; k < n; k++ {
					if j == k {
						continue
					}
					hosts[j].Peerstore().AddAddrs(hostsInfo[k].ID, hostsInfo[k].Addrs, peerstore.PermanentAddrTTL)
				}
				ctx = log.WithTopic(ctx, "lcast")
				err := casts[node].Propose(ctx, duty, data)
				require.NoError(t, err)
			}(j)
		}
	}

	var actual []core.UnsignedDataSet
	for i := 0; i < slots*n; i++ {
		actual = append(actual, <-resolved)
	}

	for _, expect := range expected {
		var count int
		for _, resolved := range actual {
			for j := 0; j < n; j++ {
				a := resolved[pubkeysByIdx[eth2p0.ValidatorIndex(j)]]
				b := expect[pubkeysByIdx[eth2p0.ValidatorIndex(j)]]
				if bytes.Equal(a, b) {
					count++
				}
			}
		}
		require.Equal(t, n*slots, count, expect)
	}
}

func createHost(t *testing.T, port int) host.Host {
	t.Helper()
	pkey, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)

	listen, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", port))
	require.NoError(t, err)

	h, err := libp2p.New([]libp2p.Option{
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Identity(pkey),
		libp2p.ListenAddrs(listen),
		libp2p.Security(noise.ID, noise.New),
	}...)
	require.NoError(t, err)

	return h
}
