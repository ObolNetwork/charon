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

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

// positionalPeerMap builds a peer-to-node-index map where each peer's share index is its position
// plus one, matching the default cluster layout.
func positionalPeerMap(peers []peer.ID) map[peer.ID]cluster.NodeIdx {
	peerMap := make(map[peer.ID]cluster.NodeIdx, len(peers))
	for i, p := range peers {
		peerMap[p] = cluster.NodeIdx{PeerIdx: i, ShareIdx: i + 1}
	}

	return peerMap
}

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
		ex, err := newExchanger(hosts[i], i, peers, positionalPeerMap(peers), expectedSigTypes, 8*time.Second)
		require.NoError(t, err)

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

	ex, err := newExchanger(h, 0, peers, positionalPeerMap(peers), []sigType{sigLock}, time.Second)
	require.NoError(t, err)

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

// TestExchangerRejectsMismatchedShareIndex verifies the sender->shareIdx binding in the lock-hash
// exchange: a peer may only contribute partial signatures under its own share index.
//
// The exchange defers cryptographic verification until aggregation, so partial signatures are
// accepted at receive time without checking their signature. newExchanger therefore binds each
// received partial signature to its authenticated sender (shareIdx == peerIdx+1), consistent with
// the sender check in nodesigs.go.
//
// This drives the real /charon/parsigex/2.0.0 receive path: one node broadcasts partial signatures
// for a pubkey outside the cluster under every share index. Every share index other than that
// node's own is rejected, so the outside pubkey never reaches the threshold, while the honest
// exchange for the real validator completes with a full set of shares.
func TestExchangerRejectsMismatchedShareIndex(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// threshold = len(peers), so reaching it for a single pubkey needs this many distinct share
	// indices, which one sender can no longer supply on its own.
	const nodes = 4

	var (
		peers     []peer.ID
		hosts     []host.Host
		hostsInfo []peer.AddrInfo
	)

	for range nodes {
		h := testutil.CreateHost(t, testutil.AvailableAddr(t))
		hostsInfo = append(hostsInfo, peer.AddrInfo{ID: h.ID(), Addrs: h.Addrs()})
		peers = append(peers, h.ID())
		hosts = append(hosts, h)
	}

	// Connect every host to its peers so exchange broadcasts reach live handlers.
	for i := range nodes {
		for j := range nodes {
			if i == j {
				continue
			}

			hosts[i].Peerstore().AddAddrs(hostsInfo[j].ID, hostsInfo[j].Addrs, peerstore.PermanentAddrTTL)
		}
	}

	exchangers := make([]*exchanger, nodes)
	for i := range nodes {
		ex, err := newExchanger(hosts[i], i, peers, positionalPeerMap(peers), []sigType{sigLock}, 8*time.Second)
		require.NoError(t, err)

		exchangers[i] = ex
	}

	realPk := testutil.RandomCorePubKey(t)    // The cluster's genuine distributed validator.
	outsidePk := testutil.RandomCorePubKey(t) // A pubkey that is not part of the cluster.

	// otherNode (peer index 1) has share index 2 as its own. It broadcasts partial signatures for
	// outsidePk under every share index over the authenticated parsigex protocol. Every peer's
	// sender->shareIdx binding must reject every share index other than otherNode's own, so outsidePk
	// can never reach the threshold anywhere.
	const otherNode = 1

	sigLockDuty := core.NewSignatureDuty(uint64(sigLock))

	for shareIdx := 1; shareIdx <= nodes; shareIdx++ {
		set := core.ParSignedDataSet{
			outsidePk: core.NewPartialSignature(testutil.RandomCoreSignature(), shareIdx),
		}
		require.NoError(t, exchangers[otherNode].sigex.Broadcast(ctx, sigLockDuty, set))
	}

	// Every node runs the honest lock-hash exchange for the single real validator, each contributing
	// only its own share. The real validator reaches the threshold legitimately and the exchange
	// resolves with real data.
	var wg sync.WaitGroup

	results := make([]map[core.PubKey][]core.ParSignedData, nodes)
	errs := make([]error, nodes)

	for i := range nodes {
		wg.Add(1)

		go func(node int) {
			defer wg.Done()

			set := core.ParSignedDataSet{
				realPk: core.NewPartialSignature(testutil.RandomCoreSignature(), node+1),
			}
			results[node], errs[node] = exchangers[node].exchange(ctx, sigLock, set)
		}(i)
	}

	wg.Wait()

	// The outside pubkey never reached the threshold, so no exchange result contains it; the real
	// validator is present with a full set of shares.
	for i := range nodes {
		require.NoErrorf(t, errs[i], "node %d exchange failed", i)
		require.Containsf(t, results[i], realPk, "node %d missing the real validator", i)
		require.Lenf(t, results[i][realPk], nodes, "node %d has an unexpected number of shares", i)
		require.NotContainsf(t, results[i], outsidePk, "node %d accepted the outside pubkey", i)
	}
}

// TestVerifyPeerShareIdx covers the sender->shareIdx binding, including a non-contiguous layout where
// a peer's assigned share index does not equal its position (as when earlier operators are removed).
func TestVerifyPeerShareIdx(t *testing.T) {
	const (
		self    = peer.ID("self")
		other   = peer.ID("other")
		unknown = peer.ID("unknown")
	)

	// "other" is the second peer but keeps share index 4, e.g. after operators with lower indices
	// have been removed.
	peerMap := map[peer.ID]cluster.NodeIdx{
		self:  {PeerIdx: 0, ShareIdx: 1},
		other: {PeerIdx: 1, ShareIdx: 4},
	}

	tests := []struct {
		name     string
		sender   peer.ID
		shareIdx int
		wantErr  string
	}{
		{name: "own share index accepted", sender: self, shareIdx: 1},
		{name: "assigned non-contiguous share index accepted", sender: other, shareIdx: 4},
		{name: "mismatched share index rejected", sender: other, shareIdx: 2, wantErr: "share index does not match"},
		{name: "another peer's share index rejected", sender: self, shareIdx: 4, wantErr: "share index does not match"},
		{name: "non-positive share index rejected", sender: self, shareIdx: 0, wantErr: "share index does not match"},
		{name: "unknown sender rejected", sender: unknown, shareIdx: 1, wantErr: "unknown peer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := core.NewPartialSignature(testutil.RandomCoreSignature(), tt.shareIdx)

			err := verifyPeerShareIdx(peerMap, tt.sender, data)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}

// TestNewExchangerRejectsIncompletePeerMap ensures construction fails fast when a peer has no valid
// share index, rather than silently rejecting its partial signatures and timing out.
func TestNewExchangerRejectsIncompletePeerMap(t *testing.T) {
	h := testutil.CreateHost(t, testutil.AvailableAddr(t))
	peers := []peer.ID{h.ID(), peer.ID("missing")}

	peerMap := map[peer.ID]cluster.NodeIdx{
		h.ID(): {PeerIdx: 0, ShareIdx: 1},
	}

	_, err := newExchanger(h, 0, peers, peerMap, []sigType{sigLock}, time.Second)
	require.ErrorContains(t, err, "missing valid share index")
}
