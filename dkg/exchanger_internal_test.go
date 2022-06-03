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

package dkg

import (
	"context"
	"reflect"
	"sync"
	"testing"

	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

// TODO(dhruv): add tests for negative scenarios (take inspiration from core/qbft/qbft_internal_test).
func TestExchanger(t *testing.T) {
	ctx := context.Background()

	const (
		dvs   = 3
		nodes = 4
	)

	// Create pubkeys for each DV
	pubkeys := make([]core.PubKey, dvs)
	for i := 0; i < dvs; i++ {
		pubkeys[i] = testutil.RandomCorePubKey(t)
	}

	// Expected data is what is desired at the end of exchange
	expectedData := make(map[core.PubKey][]core.ParSignedData)
	for i := 0; i < dvs; i++ {
		set := make([]core.ParSignedData, nodes)
		for j := 0; j < nodes; j++ {
			set[j] = core.NewPartialSignature(testutil.RandomCoreSignature(), j+1)
		}
		expectedData[pubkeys[i]] = set
	}

	dataToBeSent := make(map[int]core.ParSignedDataSet)
	for pk, psigs := range expectedData {
		for _, psig := range psigs {
			_, ok := dataToBeSent[psig.ShareIdx-1]
			if !ok {
				dataToBeSent[psig.ShareIdx-1] = make(core.ParSignedDataSet)
			}
			dataToBeSent[psig.ShareIdx-1][pk] = psig
		}
	}

	var (
		peers      []peer.ID
		hosts      []host.Host
		hostsInfo  []peer.AddrInfo
		exchangers []*exchanger
	)

	// Create hosts
	for i := 0; i < nodes; i++ {
		h := testutil.CreateHost(t, testutil.AvailableAddr(t))
		info := peer.AddrInfo{
			ID:    h.ID(),
			Addrs: h.Addrs(),
		}
		hostsInfo = append(hostsInfo, info)
		peers = append(peers, h.ID())
		hosts = append(hosts, h)
	}

	// Connect each host with its peers
	for i := 0; i < nodes; i++ {
		for j := 0; j < nodes; j++ {
			if i == j {
				continue
			}
			hosts[i].Peerstore().AddAddrs(hostsInfo[j].ID, hostsInfo[j].Addrs, peerstore.PermanentAddrTTL)
		}
	}

	for i := 0; i < nodes; i++ {
		ex := newExchanger(hosts[i], i, peers, dvs)
		exchangers = append(exchangers, ex)
	}

	var actual []map[core.PubKey][]core.ParSignedData
	var wg sync.WaitGroup
	for i := 0; i < nodes; i++ {
		wg.Add(1)
		go func(node int) {
			defer wg.Done()

			data, err := exchangers[node].exchange(ctx, sigLock, dataToBeSent[node])
			require.NoError(t, err)

			actual = append(actual, data)
		}(i)
	}
	wg.Wait()

	for i := 0; i < nodes; i++ {
		reflect.DeepEqual(actual[i], expectedData)
	}
}
