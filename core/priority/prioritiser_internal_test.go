// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package priority

import (
	"context"
	"encoding/hex"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestHashProto(t *testing.T) {
	tests := []struct {
		name     string
		msg      proto.Message
		expected string
	}{
		{
			name:     "empty_priority_msg",
			msg:      &pbv1.PriorityMsg{},
			expected: "0x0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:     "priority_msg_peer1",
			msg:      &pbv1.PriorityMsg{PeerId: "peer1"},
			expected: "0x1a05706565723100000000000000000000000000000000000000000000000000",
		},
		{
			name:     "priority_msg_peer2",
			msg:      &pbv1.PriorityMsg{PeerId: "peer2"},
			expected: "0x1a05706565723200000000000000000000000000000000000000000000000000",
		},
		{
			name: "priority_msg_with_signature",
			msg: &pbv1.PriorityMsg{
				PeerId:    "peer1",
				Signature: []byte{0xde, 0xad, 0xbe, 0xef},
			},
			expected: "0x1a0570656572312204deadbeef00000000000000000000000000000000000000",
		},
		{
			name:     "empty_priority_result",
			msg:      &pbv1.PriorityResult{},
			expected: "0x0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name: "priority_result_with_msgs",
			msg: &pbv1.PriorityResult{
				Msgs: []*pbv1.PriorityMsg{{PeerId: "peer1"}},
			},
			expected: "0x0a071a0570656572310000000000000000000000000000000000000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hashProto(tt.msg)
			require.NoError(t, err)
			require.Equal(t, tt.expected, "0x"+hex.EncodeToString(got[:]))
		})
	}
}

// gaterSlot is the highest duty slot allowed by the gater used in the tests below.
const gaterSlot = 100

// TestHandleRequestGatesDuty asserts a gated duty is rejected before any per-duty
// state is allocated for it, while an allowed duty still reaches the deadliner and
// gets a request buffer.
func TestHandleRequestGatesDuty(t *testing.T) {
	tests := []struct {
		name      string
		slot      uint64
		wantErr   string
		wantState bool
	}{
		{
			name:    "gated far future duty",
			slot:    gaterSlot + 1,
			wantErr: "invalid duty",
		},
		{
			name: "allowed duty",
			slot: gaterSlot,
			// No instance runs for an unsolicited request, so it blocks until the context expires.
			wantErr:   "timeout waiting for proposed priorities",
			wantState: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pID, deadliner, p := newGatedPrioritiser(t)

			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()

			_, err := p.handleRequest(ctx, pID, infoSyncMsg(pID, test.slot))
			require.ErrorContains(t, err, test.wantErr)

			p.reqMu.Lock()
			gotBuffers := len(p.reqBuffers)
			p.reqMu.Unlock()

			if test.wantState {
				require.Len(t, deadliner.Added(), 1)
				require.Equal(t, 1, gotBuffers)
			} else {
				require.Empty(t, deadliner.Added(), "gated duty must not reach the deadliner")
				require.Zero(t, gotBuffers, "gated duty must not retain a request buffer")
			}
		})
	}
}

// TestHandleRequestFloodGated asserts a peer flooding distinct far-future duty slots
// retains no per-duty state. Ungated, each distinct slot leaked a deadliner entry that
// only expires at its (far future) deadline plus a request buffer keyed by that duty.
func TestHandleRequestFloodGated(t *testing.T) {
	pID, deadliner, p := newGatedPrioritiser(t)

	for i := range uint64(100) {
		// Gated requests return immediately. The timeout only bounds an ungated
		// request, which blocks forever waiting on an instance that never runs.
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Millisecond)

		_, err := p.handleRequest(ctx, pID, infoSyncMsg(pID, gaterSlot+1+i))

		cancel()

		require.ErrorContains(t, err, "invalid duty")
	}

	p.reqMu.Lock()
	defer p.reqMu.Unlock()

	require.Empty(t, p.reqBuffers)
	require.Empty(t, deadliner.Added())
}

// newGatedPrioritiser returns a prioritiser gating duties above gaterSlot, along with
// the peer ID it accepts requests from and the deadliner it was wired with.
func newGatedPrioritiser(t *testing.T) (peer.ID, *recordingDeadliner, *Prioritiser) {
	t.Helper()

	pID, err := p2p.PeerIDFromKey(testutil.GenerateInsecureK1Key(t, 0).PubKey())
	require.NoError(t, err)

	deadliner := new(recordingDeadliner)

	p := newInternal(nil, []peer.ID{pID}, 1, nil, nopRegisterHandler, nopConsensus{},
		func(*pbv1.PriorityMsg) error { return nil }, time.Hour, deadliner,
		func(duty core.Duty) bool { return duty.Slot <= gaterSlot })

	return pID, deadliner, p
}

func infoSyncMsg(pID peer.ID, slot uint64) *pbv1.PriorityMsg {
	return &pbv1.PriorityMsg{
		Duty:   core.DutyToProto(core.NewInfoSyncDuty(slot)),
		PeerId: pID.String(),
	}
}

// recordingDeadliner records the duties added to it. It implements core.Deadliner.
type recordingDeadliner struct {
	mu    sync.Mutex
	added []core.Duty
}

func (d *recordingDeadliner) Add(duty core.Duty) core.DeadlineStatus {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.added = append(d.added, duty)

	return core.DeadlineScheduled
}

func (*recordingDeadliner) C() <-chan core.Duty { return nil }

func (d *recordingDeadliner) Added() []core.Duty {
	d.mu.Lock()
	defer d.mu.Unlock()

	return slices.Clone(d.added)
}

// nopConsensus implements Consensus and does nothing.
type nopConsensus struct{}

func (nopConsensus) ProposePriority(context.Context, core.Duty, *pbv1.PriorityResult) error {
	return nil
}

func (nopConsensus) SubscribePriority(func(context.Context, core.Duty, *pbv1.PriorityResult) error) {
}

// nopRegisterHandler implements p2p.RegisterHandlerFunc and registers nothing.
func nopRegisterHandler(string, host.Host, protocol.ID, func() proto.Message,
	p2p.HandlerFunc, ...p2p.SendRecvOption,
) {
}
