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

// bundleKind abstracts delivering a bundle of one type via its p2p handler and
// receiving it from the corresponding incoming board channel.
type bundleKind struct {
	name    string
	deliver func(ctx context.Context, t *testing.T, board *Board, from peer.ID, idx uint32, session, sig []byte)
	receive func(t *testing.T, board *Board) (uint32, bool)
}

func bundleKinds() []bundleKind {
	return []bundleKind{
		{
			name: "deal",
			deliver: func(ctx context.Context, t *testing.T, board *Board, from peer.ID, idx uint32, session, sig []byte) {
				t.Helper()

				protoBundle, err := DealBundleToProto(kdkg.DealBundle{
					DealerIndex: idx,
					Deals: []kdkg.Deal{
						{
							ShareIndex:     1,
							EncryptedShare: []byte{1, 2, 3},
						},
					},
					Public:    []kyber.Point{RandomPoint(t)},
					SessionID: session,
					Signature: sig,
				})
				require.NoError(t, err)

				_, _, err = board.handleDealBundleMessage(ctx, from, protoBundle)
				require.NoError(t, err)
			},
			receive: func(t *testing.T, board *Board) (uint32, bool) {
				t.Helper()

				select {
				case bundle := <-board.IncomingDeal():
					return bundle.DealerIndex, true
				case <-time.After(time.Second):
					return 0, false
				}
			},
		},
		{
			name: "response",
			deliver: func(ctx context.Context, t *testing.T, board *Board, from peer.ID, idx uint32, session, sig []byte) {
				t.Helper()

				protoBundle, err := ResponseBundleToProto(kdkg.ResponseBundle{
					ShareIndex: idx,
					Responses: []kdkg.Response{
						{
							DealerIndex: 1,
							Status:      true,
						},
					},
					SessionID: session,
					Signature: sig,
				})
				require.NoError(t, err)

				_, _, err = board.handleResponseBundleMessage(ctx, from, protoBundle)
				require.NoError(t, err)
			},
			receive: func(t *testing.T, board *Board) (uint32, bool) {
				t.Helper()

				select {
				case bundle := <-board.IncomingResponse():
					return bundle.ShareIndex, true
				case <-time.After(time.Second):
					return 0, false
				}
			},
		},
		{
			name: "justification",
			deliver: func(ctx context.Context, t *testing.T, board *Board, from peer.ID, idx uint32, session, sig []byte) {
				t.Helper()

				protoBundle, err := JustificationBundleToProto(kdkg.JustificationBundle{
					DealerIndex: idx,
					Justifications: []kdkg.Justification{
						{
							ShareIndex: 1,
							Share:      RandomScalar(t),
						},
					},
					SessionID: session,
					Signature: sig,
				})
				require.NoError(t, err)

				_, _, err = board.handleJustificationBundleMessage(ctx, from, protoBundle)
				require.NoError(t, err)
			},
			receive: func(t *testing.T, board *Board) (uint32, bool) {
				t.Helper()

				select {
				case bundle := <-board.IncomingJustification():
					return bundle.DealerIndex, true
				case <-time.After(time.Second):
					return 0, false
				}
			},
		},
	}
}

// TestBoardBuffersEarlyBundles verifies that bundles arriving before the kyber
// protocol starts reading the incoming board channels are buffered and delivered
// later, instead of being dropped when the p2p request context expires. This
// happens when peers start the DKG a few seconds earlier than this node.
func TestBoardBuffersEarlyBundles(t *testing.T) {
	const (
		numNodes  = 4
		threshold = 3
	)

	for _, kind := range bundleKinds() {
		t.Run(kind.name, func(t *testing.T) {
			board, nodes, session := newTestBoard(t, numNodes, threshold)

			// Deliver bundles from all other peers before anything reads the
			// incoming channel. Each handler call gets a short-lived context,
			// like an expiring p2p request context.
			for i := 1; i < numNodes; i++ {
				ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
				kind.deliver(ctx, t, board, nodes[i].NodeHost.ID(), uint32(i), session, []byte{byte(i)})
				cancel()
			}

			// All early bundles must be delivered once the protocol starts reading.
			received := make(map[uint32]bool)

			for i := 1; i < numNodes; i++ {
				idx, ok := kind.receive(t, board)
				if !ok {
					require.Failf(t, "early bundle dropped", "received %d of %d bundles", len(received), numNodes-1)
				}

				received[idx] = true
			}

			require.Len(t, received, numNodes-1)
		})
	}
}

// TestBoardAcceptsRedeliveryAfterDrop verifies that a bundle dropped because the
// request context expired is not recorded as a duplicate, so a redelivery of the
// same bundle is accepted.
func TestBoardAcceptsRedeliveryAfterDrop(t *testing.T) {
	const (
		numNodes  = 4
		threshold = 3
	)

	for _, kind := range bundleKinds() {
		t.Run(kind.name, func(t *testing.T) {
			board, nodes, session := newTestBoard(t, numNodes, threshold)
			from := nodes[1].NodeHost.ID()

			// Fill the channel buffer plus the forwarder's in-flight slot so the
			// next delivery blocks and gets dropped.
			total := numNodes + 1
			for i := range total {
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				kind.deliver(ctx, t, board, from, uint32(i), session, []byte{byte(i)})
				cancel()
			}

			// This bundle is dropped since nothing is reading yet and the buffer is full.
			droppedIdx := uint32(total)
			droppedSig := []byte{byte(total)}

			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			kind.deliver(ctx, t, board, from, droppedIdx, session, droppedSig)
			cancel()

			// Drain the buffered bundles.
			for range total {
				_, ok := kind.receive(t, board)
				require.True(t, ok, "buffered bundle not delivered")
			}

			// Redeliver the dropped bundle. It must not be refused as a duplicate.
			ctx, cancel = context.WithTimeout(t.Context(), time.Second)
			defer cancel()

			kind.deliver(ctx, t, board, from, droppedIdx, session, droppedSig)

			idx, ok := kind.receive(t, board)
			require.True(t, ok, "redelivered bundle refused as duplicate")
			require.Equal(t, droppedIdx, idx)
		})
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
