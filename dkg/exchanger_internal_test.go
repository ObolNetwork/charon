// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"

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
	for i := range dvs {
		pubkeys[i] = testutil.RandomCorePubKey(t)
	}

	// Expected data is what is desired at the end of exchange
	expectedData := make(map[core.PubKey][]core.ParSignedData)
	for i := range dvs {
		set := make([]core.ParSignedData, nodes)
		for j := range nodes {
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

		expectedSigTypes = []sigType{
			sigLock,
			sigDepositData,
			sigValidatorRegistration,
		}
	)

	// Create hosts
	for range nodes {
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
	for i := range nodes {
		for j := range nodes {
			if i == j {
				continue
			}

			hosts[i].Peerstore().AddAddrs(hostsInfo[j].ID, hostsInfo[j].Addrs, peerstore.PermanentAddrTTL)
		}
	}

	for i := range nodes {
		ex := newExchanger(hosts[i], i, peers, expectedSigTypes, 8*time.Second)
		exchangers = append(exchangers, ex)
	}

	type respStruct struct {
		data    map[core.PubKey][]core.ParSignedData
		err     error
		sigType sigType
	}

	respChan := make(chan respStruct)

	var wg sync.WaitGroup

	// send multiple (supported) messages at the same time, showing that exchanger can exchange messages of various
	// sigTypes concurrently
	for i := range nodes {
		wg.Add(2)

		go func(node int) {
			defer wg.Done()

			data, err := exchangers[node].exchange(ctx, sigDepositData, dataToBeSent[node])

			respChan <- respStruct{
				data:    data,
				err:     err,
				sigType: sigDepositData,
			}
		}(i)
		go func(node int) {
			defer wg.Done()

			data, err := exchangers[node].exchange(ctx, sigValidatorRegistration, dataToBeSent[node])

			respChan <- respStruct{
				data:    data,
				err:     err,
				sigType: sigValidatorRegistration,
			}
		}(i)
	}

	for i := range nodes {
		wg.Add(1)

		go func(node int) {
			defer wg.Done()

			data, err := exchangers[node].exchange(ctx, sigLock, dataToBeSent[node])

			respChan <- respStruct{
				data:    data,
				err:     err,
				sigType: sigLock,
			}
		}(i)
	}

	go func() {
		wg.Wait()
		close(respChan) // Closes response channel once all the goroutines are done with writing.
	}()

	actual := make(sigTypeStore)

	for res := range respChan {
		require.NoError(t, res.err)
		actual[res.sigType] = res.data
	}

	// test that data we expected arrived, for each sigType
	for _, data := range actual {
		reflect.DeepEqual(data, expectedData)
	}

	// test that all sigTypes expected to arrive actually arrived
	for _, expectedSigType := range expectedSigTypes {
		_, ok := actual[expectedSigType]
		require.True(t, ok, "missing sigType %d from received data", expectedSigType)
	}

	// require that we encountered all the sigTypes expected
	require.Len(t, actual, len(expectedSigTypes))
}

// TestExchangerPushPsigsNeverBlocks fires pushPsigs repeatedly with no exchange call draining
// results, which must not block. A previous implementation used a shared size-1 channel that
// deadlocked once full, especially when pushPsigs ran synchronously on the exchange goroutine.
func TestExchangerPushPsigsNeverBlocks(t *testing.T) {
	ctx := context.Background()

	h := testutil.CreateHost(t, testutil.AvailableAddr(t))
	peers := []peer.ID{h.ID()}

	ex := newExchanger(h, 0, peers, []sigType{sigLock}, time.Second)

	duty := core.NewSignatureDuty(uint64(sigLock))

	newSet := func() map[core.PubKey][]core.ParSignedData {
		return map[core.PubKey][]core.ParSignedData{
			testutil.RandomCorePubKey(t): {core.NewPartialSignature(testutil.RandomCoreSignature(), 1)},
		}
	}

	// Fire the threshold subscriber several times without any exchange call consuming results.
	const iterations = 5

	errs := make(chan error, 1)
	done := make(chan struct{})

	go func() {
		for range iterations {
			if err := ex.pushPsigs(ctx, duty, newSet()); err != nil {
				errs <- err
				return
			}
		}

		close(done)
	}()

	select {
	case <-done:
	case err := <-errs:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("pushPsigs deadlocked")
	}
}
