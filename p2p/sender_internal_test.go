// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"context"
	"sync"
	"testing"
	"time"

	fuzz "github.com/google/gofuzz"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/app/errors"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
)

func TestSenderAddResult(t *testing.T) {
	sender := new(Sender)
	peerID := peer.ID("test")
	failure := errors.New("failure")
	success := error(nil)

	assertFailing := func(t *testing.T, expect bool) {
		t.Helper()
		var state peerState
		if val, ok := sender.states.Load(peerID); ok {
			state = val.(peerState)
		}
		require.Equal(t, expect, state.failing)
	}

	add := func(result error) {
		sender.addResult(context.Background(), peerID, result)
	}

	assertFailing(t, false) // Start not failing
	add(failure)
	assertFailing(t, true) // Single failure changes state to failing.
	add(failure)
	assertFailing(t, true) // Still failing.
	add(success)
	assertFailing(t, true) // Still failing.
	add(success)
	assertFailing(t, true) // Still failing.
	add(success)
	assertFailing(t, false) // Hysteresis success changes state to success.
	add(success)
	assertFailing(t, false) // Still success
	add(success)
	assertFailing(t, false) // Still success
	add(failure)
	assertFailing(t, true) // Single failure changes state to failing.

	// TODO(corver): Assert logs
	// INFO P2P sending failing {"peer": "better-week"}
	// INFO P2P sending recovered {"peer": "better-week"}
	// INFO P2P sending failing {"peer": "better-week"}
}

func TestSenderRetry(t *testing.T) {
	sender := new(Sender)
	ctx := context.Background()

	h := new(testHost)
	err := sender.SendReceive(ctx, h, "", nil, new(pbv1.Duty), "")
	require.ErrorIs(t, err, network.ErrReset)
	require.Equal(t, 2, h.Count())

	h = new(testHost)
	err = sender.SendAsync(ctx, h, "", "", nil)
	require.Nil(t, err)
	require.Eventually(t, func() bool {
		return h.Count() == 2
	}, time.Second, time.Millisecond)
}

type testHost struct {
	host.Host
	mu    sync.Mutex
	count int
}

func (h *testHost) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.count
}

func (h *testHost) NewStream(context.Context, peer.ID, ...protocol.ID) (network.Stream, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.count++

	return nil, network.ErrReset
}

func TestProtocolPrefix(b *testing.T) {
	require.EqualValues(b, "charon/peer_info/1.0.0", protocolPrefix("charon/peer_info/1.0.0"))
	require.EqualValues(b, "charon/peer_info/1.*", protocolPrefix("charon/peer_info/1.0.0", "charon/peer_info/1.1.0"))
	require.EqualValues(b, "charon/peer_info/*", protocolPrefix("charon/peer_info/1.0.0", "charon/peer_info/2.0.0", "charon/peer_info/3.0.0"))
}

func TestIsZeroProto(t *testing.T) {
	for _, msg := range []proto.Message{
		new(pbv1.Duty),
		new(pbv1.ConsensusMsg),
		new(timestamppb.Timestamp),
	} {
		require.False(t, isZeroProto(nil))
		require.True(t, isZeroProto(msg))
		fuzz.New().NilChance(0).Fuzz(msg)
		require.False(t, isZeroProto(msg))

		anyMsg, err := anypb.New(msg)
		require.NoError(t, err)
		require.False(t, isZeroProto(anyMsg))
	}
}

func TestNonZeroResponse(t *testing.T) {
	ctx := context.Background()
	err := SendReceive(ctx, nil, "", nil, &pbv1.Duty{Slot: 1}, "")
	require.ErrorContains(t, err, "bug: response proto must be zero value")
}
