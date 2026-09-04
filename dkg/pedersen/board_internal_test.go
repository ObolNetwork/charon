// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen

import (
	"context"
	"testing"
	"time"

	"github.com/drand/kyber"
	kdkg "github.com/drand/kyber/share/dkg"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/testutil"
)

// TestBoardBuffersEarlyDealBundles verifies that deal bundles arriving before the
// kyber protocol starts reading IncomingDeal are buffered and delivered later,
// instead of being dropped when the p2p request context expires. This happens when
// peers start the DKG a few seconds earlier than this node.
func TestBoardBuffersEarlyDealBundles(t *testing.T) {
	const (
		numNodes  = 4
		threshold = 3
	)

	board, nodes, session := newTestBoard(t, numNodes, threshold)

	// Deliver deal bundles from all other peers before anything reads
	// IncomingDeal. Each handler call gets a short-lived context, like an
	// expiring p2p request context.
	for i := 1; i < numNodes; i++ {
		protoBundle, err := DealBundleToProto(testDealBundle(t, uint32(i), session, []byte{byte(i)}))
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		_, _, err = board.handleDealBundleMessage(ctx, nodes[i].NodeHost.ID(), protoBundle)

		cancel()
		require.NoError(t, err)
	}

	// All early bundles must be delivered once the protocol starts reading.
	received := make(map[uint32]bool)

	for i := 1; i < numNodes; i++ {
		select {
		case bundle := <-board.IncomingDeal():
			received[bundle.DealerIndex] = true
		case <-time.After(time.Second):
			require.Failf(t, "early deal bundle dropped", "received %d of %d bundles", len(received), numNodes-1)
		}
	}

	require.Len(t, received, numNodes-1)
}

// TestBoardAcceptsRedeliveryAfterDrop verifies that a deal bundle dropped because
// the request context expired is not recorded as a duplicate, so a redelivery of
// the same bundle is accepted.
func TestBoardAcceptsRedeliveryAfterDrop(t *testing.T) {
	const (
		numNodes  = 4
		threshold = 3
	)

	board, nodes, session := newTestBoard(t, numNodes, threshold)

	// Fill the deal channel buffer plus the forwarder's in-flight slot so the
	// next delivery blocks and gets dropped.
	total := numNodes + 1
	for i := range total {
		protoBundle, err := DealBundleToProto(testDealBundle(t, uint32(i), session, []byte{byte(i)}))
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		_, _, err = board.handleDealBundleMessage(ctx, nodes[1].NodeHost.ID(), protoBundle)

		cancel()
		require.NoError(t, err)
	}

	// This bundle is dropped since nothing is reading yet and the buffer is full.
	droppedBundle, err := DealBundleToProto(testDealBundle(t, uint32(total), session, []byte{byte(total)}))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	_, _, err = board.handleDealBundleMessage(ctx, nodes[1].NodeHost.ID(), droppedBundle)

	cancel()
	require.NoError(t, err)

	// Drain the buffered bundles.
	for range total {
		select {
		case <-board.IncomingDeal():
		case <-time.After(time.Second):
			require.Fail(t, "buffered deal bundle not delivered")
		}
	}

	// Redeliver the dropped bundle. It must not be refused as a duplicate.
	ctx, cancel = context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	_, _, err = board.handleDealBundleMessage(ctx, nodes[1].NodeHost.ID(), droppedBundle)
	require.NoError(t, err)

	select {
	case bundle := <-board.IncomingDeal():
		require.Equal(t, uint32(total), bundle.DealerIndex)
	case <-time.After(time.Second):
		require.Fail(t, "redelivered deal bundle refused as duplicate")
	}
}

func newTestBoard(t *testing.T, numNodes, threshold int) (*Board, []*TestNode, []byte) {
	t.Helper()

	var (
		peers   []peer.ID
		peerMap = make(map[peer.ID]cluster.NodeIdx)
		session = testutil.RandomArray32()
	)

	nodes := make([]*TestNode, numNodes)
	for i := range numNodes {
		nodes[i] = NewTestNode(t, i)
		peerMap[nodes[i].NodeHost.ID()] = nodes[i].NodeIdx
		peers = append(peers, nodes[i].NodeHost.ID())
	}

	nodes[0].InitBoard(t, threshold, peers, peerMap, session[:])

	return nodes[0].Board, nodes, session[:]
}

func testDealBundle(t *testing.T, dealerIdx uint32, session, sig []byte) kdkg.DealBundle {
	t.Helper()

	return kdkg.DealBundle{
		DealerIndex: dealerIdx,
		Deals: []kdkg.Deal{
			{
				ShareIndex:     1,
				EncryptedShare: []byte{1, 2, 3},
			},
		},
		Public:    []kyber.Point{RandomPoint(t)},
		SessionID: session,
		Signature: sig,
	}
}
