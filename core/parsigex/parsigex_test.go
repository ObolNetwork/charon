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
	"sync"
	"testing"

	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
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

	pubkey := testutil.RandomCorePubKey(t)
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

	// create ParSigEx components for each host
	for i := 0; i < n; i++ {
		sigex := parsigex.NewParSigEx(hosts[i], i, peers)
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
		go func(node int) {
			defer wg.Done()
			// broadcast partially signed data
			require.NoError(t, parsigexs[node].Broadcast(context.Background(), duty, data))
		}(i)
	}

	wg.Wait()
}
