// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"reflect"
	"sync"
	"testing"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
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
		ex := newExchanger(hosts[i], i, peers, dvs, []sigType{
			sigLock,
			sigDepositData,
			sigValidatorRegistration,
		})
		exchangers = append(exchangers, ex)
	}

	respChan := make(chan map[core.PubKey][]core.ParSignedData)
	var wg sync.WaitGroup

	// send multiple (supported) messages at the same time, showing that exchanger can exchange messages of various
	// sigTypes concurrently
	for i := 0; i < nodes; i++ {
		wg.Add(2)
		go func(node int) {
			defer wg.Done()

			data, err := exchangers[node].exchange(ctx, sigDepositData, dataToBeSent[node])
			require.NoError(t, err)

			respChan <- data
		}(i)
		go func(node int) {
			defer wg.Done()

			data, err := exchangers[node].exchange(ctx, sigValidatorRegistration, dataToBeSent[node])
			require.NoError(t, err)

			respChan <- data
		}(i)
	}

	for i := 0; i < nodes; i++ {
		wg.Add(1)
		go func(node int) {
			defer wg.Done()

			data, err := exchangers[node].exchange(ctx, sigLock, dataToBeSent[node])
			require.NoError(t, err)

			respChan <- data
		}(i)
	}

	go func() {
		wg.Wait()
		close(respChan) // Closes response channel once all the goroutines are done with writing.
	}()

	var actual []map[core.PubKey][]core.ParSignedData
	for res := range respChan {
		actual = append(actual, res)
	}

	for i := 0; i < nodes; i++ {
		reflect.DeepEqual(actual[i], expectedData)
	}
}
