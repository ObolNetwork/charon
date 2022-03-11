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

package parsigex_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
	noise "github.com/libp2p/go-libp2p-noise"
	"github.com/libp2p/go-tcp-transport"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/parsigex"
	"github.com/obolnetwork/charon/testutil"
)

func TestParSigEx(t *testing.T) {
	n := 3
	duty := core.Duty{
		Slot: 123,
		Type: core.DutyAttester,
	}
	portStart := 15000

	pubkey := testutil.RandomPubKey(t)
	data := core.ParSignedDataSet{
		pubkey: core.ParSignedData{
			Data:      []byte("partially signed data"),
			Signature: nil,
			ShareIdx:  0,
		},
	}

	var (
		parsigexs []*parsigex.ParSigEx
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

	// create ParSigEx components for each host
	for i := 0; i < n; i++ {
		sigex := parsigex.NewParSigEx(hosts[i], hosts[i].ID(), peers)
		sigex.Subscribe(func(_ context.Context, d core.Duty, set core.ParSignedDataSet) error {
			require.Equal(t, duty, d)
			require.Equal(t, data, set)

			return nil
		})
		parsigexs = append(parsigexs, sigex)
	}

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()

			// register other peers
			for j := 0; j < n; j++ {
				if i == j {
					continue
				}
				hosts[i].Peerstore().AddAddrs(hostsInfo[j].ID, hostsInfo[j].Addrs, peerstore.PermanentAddrTTL)
			}

			// broadcast parsigex
			require.NoError(t, parsigexs[i].Broadcast(context.Background(), duty, data))
		}()
	}

	wg.Wait()
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
