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

	"github.com/obolnetwork/charon/app/log"
)

func TestReadBoardChannel(t *testing.T) {
	var (
		peerA = peer.ID("peer-a")
		peerB = peer.ID("peer-b")
		peerC = peer.ID("peer-c")
	)

	expected := []peer.ID{peerA, peerB, peerC}
	peerIDFn := func(pk NodePubKeys) peer.ID { return pk.PeerID }

	t.Run("all messages received", func(t *testing.T) {
		ch := make(chan NodePubKeys, 3)
		for _, pid := range expected {
			ch <- NodePubKeys{PeerID: pid}
		}

		got, err := readBoardChannel(t.Context(), ch, expected, peerIDFn, time.Second)
		require.NoError(t, err)
		require.Len(t, got, 3)
	})

	t.Run("timeout reports missing peers", func(t *testing.T) {
		ch := make(chan NodePubKeys, 3)
		ch <- NodePubKeys{PeerID: peerA}

		_, err := readBoardChannel(t.Context(), ch, expected, peerIDFn, 100*time.Millisecond)
		require.ErrorContains(t, err, "timed out waiting")
	})

	t.Run("duplicates do not mask a missing peer", func(t *testing.T) {
		ch := make(chan NodePubKeys, 3)
		ch <- NodePubKeys{PeerID: peerA}

		ch <- NodePubKeys{PeerID: peerA} // Duplicate delivery of peer A.

		ch <- NodePubKeys{PeerID: peerB}

		_, err := readBoardChannel(t.Context(), ch, expected, peerIDFn, 100*time.Millisecond)
		require.ErrorContains(t, err, "timed out waiting", "peer C is still missing")
	})

	t.Run("unexpected peers are ignored", func(t *testing.T) {
		ch := make(chan NodePubKeys, 4)
		ch <- NodePubKeys{PeerID: peerA}

		ch <- NodePubKeys{PeerID: peer.ID("peer-x")} // Not part of the ceremony.

		ch <- NodePubKeys{PeerID: peerB}

		ch <- NodePubKeys{PeerID: peerC}

		got, err := readBoardChannel(t.Context(), ch, expected, peerIDFn, time.Second)
		require.NoError(t, err)
		require.Len(t, got, 3)

		for _, msg := range got {
			require.NotEqual(t, peer.ID("peer-x"), msg.PeerID)
		}
	})

	t.Run("context cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		ch := make(chan NodePubKeys, 3)

		_, err := readBoardChannel(ctx, ch, expected, peerIDFn, time.Second)
		require.ErrorContains(t, err, "context done")
	})
}

func TestForwardBundlesClosesOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	in := make(chan int)
	out := make(chan int)

	go forwardBundles(ctx, in, out)

	// Values are forwarded while the context is live.
	go func() { in <- 42 }()

	require.Equal(t, 42, <-out)

	// The output channel is closed when the context is canceled, which stops
	// kyber FastSync protocol goroutines reading from it.
	cancel()

	select {
	case _, ok := <-out:
		require.False(t, ok, "expected output channel to be closed")
	case <-time.After(time.Second):
		t.Fatal("output channel was not closed on context cancel")
	}
}

func TestBoardDropsDuplicateBundles(t *testing.T) {
	board := &Board{
		logCtx:          log.WithTopic(t.Context(), "pedersen"),
		config:          &Config{Suite: DefaultSuite},
		dealCh:          make(chan kdkg.DealBundle, 4),
		responseCh:      make(chan kdkg.ResponseBundle, 4),
		justificationCh: make(chan kdkg.JustificationBundle, 4),
		dedup:           newBundleDedup(),
	}

	pid := peer.ID("peer-a")

	t.Run("deal bundle", func(t *testing.T) {
		bundle := kdkg.DealBundle{
			DealerIndex: 1,
			Deals:       []kdkg.Deal{{ShareIndex: 1, EncryptedShare: []byte{1, 2, 3}}},
			Public:      []kyber.Point{RandomPoint(t)},
			SessionID:   []byte("session"),
			Signature:   []byte{1, 1, 1},
		}

		msg, err := DealBundleToProto(bundle)
		require.NoError(t, err)

		_, _, err = board.handleDealBundleMessage(t.Context(), pid, msg)
		require.NoError(t, err)
		require.Len(t, board.dealCh, 1)

		// Identical re-delivery is dropped.
		_, _, err = board.handleDealBundleMessage(t.Context(), pid, msg)
		require.NoError(t, err)
		require.Len(t, board.dealCh, 1)

		// A different bundle from the same dealer passes through.
		bundle.Signature = []byte{2, 2, 2}
		msg2, err := DealBundleToProto(bundle)
		require.NoError(t, err)

		_, _, err = board.handleDealBundleMessage(t.Context(), pid, msg2)
		require.NoError(t, err)
		require.Len(t, board.dealCh, 2)
	})

	t.Run("response bundle", func(t *testing.T) {
		bundle := kdkg.ResponseBundle{
			ShareIndex: 1,
			Responses:  []kdkg.Response{{DealerIndex: 1, Status: true}},
			SessionID:  []byte("session"),
			Signature:  []byte{3, 3, 3},
		}

		msg, err := ResponseBundleToProto(bundle)
		require.NoError(t, err)

		_, _, err = board.handleResponseBundleMessage(t.Context(), pid, msg)
		require.NoError(t, err)
		require.Len(t, board.responseCh, 1)

		_, _, err = board.handleResponseBundleMessage(t.Context(), pid, msg)
		require.NoError(t, err)
		require.Len(t, board.responseCh, 1)
	})

	t.Run("justification bundle", func(t *testing.T) {
		bundle := kdkg.JustificationBundle{
			DealerIndex:    1,
			Justifications: []kdkg.Justification{{ShareIndex: 1, Share: RandomScalar(t)}},
			SessionID:      []byte("session"),
			Signature:      []byte{4, 4, 4},
		}

		msg, err := JustificationBundleToProto(bundle)
		require.NoError(t, err)

		_, _, err = board.handleJustificationBundleMessage(t.Context(), pid, msg)
		require.NoError(t, err)
		require.Len(t, board.justificationCh, 1)

		_, _, err = board.handleJustificationBundleMessage(t.Context(), pid, msg)
		require.NoError(t, err)
		require.Len(t, board.justificationCh, 1)
	})
}
