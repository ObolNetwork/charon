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

func TestShareSigExchange(t *testing.T) {
	n := 3
	duty := core.Duty{
		Slot: 123,
		Type: core.DutyAttester,
	}

	pubkey := testutil.RandomCorePubKey(t)
	data := core.ShareSignedDataSet{
		pubkey: core.ShareSignedData{
			Data:      []byte("partially signed data"),
			Signature: nil,
			ShareIdx:  0,
		},
	}

	var (
		parsigexs []*parsigex.ShareSigExchange
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

	// create ShareSigExchange components for each host
	for i := 0; i < n; i++ {
		sigex := parsigex.NewShareSigExchange(hosts[i], i, peers)
		sigex.Subscribe(func(_ context.Context, d core.Duty, set core.ShareSignedDataSet) error {
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
