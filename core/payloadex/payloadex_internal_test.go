// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package payloadex

import (
	"context"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestStoreCandidate(t *testing.T) {
	const slot = 1

	contents := testutil.RandomGloasCoreVersionedEPBSProposalWithPayload()
	contents.EPBS.GloasContents.Block.Slot = slot

	roots, err := core.NewPayloadContentsRoots(contents)
	require.NoError(t, err)

	p := &PayloadEx{
		retentionFunc: func(core.Duty) (time.Time, bool) {
			return time.Now().Add(50 * time.Millisecond), true
		},
		candidates: make(map[candidateKey]core.VersionedProposal),
	}

	// A bare proposal has no contents to hold.
	require.ErrorContains(t, p.StoreCandidate(t.Context(), testutil.RandomGloasCoreVersionedEPBSProposal()), "no execution payload contents")

	// The candidate is held by its roots until the duty deadline.
	require.NoError(t, p.StoreCandidate(t.Context(), contents))

	cand, ok := p.candidate(slot, roots)
	require.True(t, ok)
	require.Equal(t, contents, cand)

	// Storing it again is idempotent.
	require.NoError(t, p.StoreCandidate(t.Context(), contents))
	require.Len(t, p.candidates, 1)

	// A slot may have several candidates, e.g. of a retried fetch, each held by its roots.
	other := testutil.RandomGloasCoreVersionedEPBSProposalWithPayload()
	other.EPBS.GloasContents.Block.Slot = slot

	otherRoots, err := core.NewPayloadContentsRoots(other)
	require.NoError(t, err)

	require.NoError(t, p.StoreCandidate(t.Context(), other))

	cand, ok = p.candidate(slot, otherRoots)
	require.True(t, ok)
	require.Equal(t, other, cand)

	cand, ok = p.candidate(slot, roots)
	require.True(t, ok)
	require.Equal(t, contents, cand)

	require.Eventually(t, func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()

		return len(p.candidates) == 0
	}, time.Second, 5*time.Millisecond)
}

func TestExchange(t *testing.T) {
	const (
		n           = 3
		proposerIdx = 0
		slot        = 1
	)

	duty := core.NewProposerDuty(slot)
	peers := newTestPeers(t, n)

	contents := testutil.RandomGloasCoreVersionedEPBSProposalWithPayload()
	contents.EPBS.GloasContents.Block.Slot = slot

	agreed, err := core.WithoutPayloadContents(contents)
	require.NoError(t, err)

	newPayloadEx := func(peerIdx int, agreed core.VersionedProposal, sent chan<- *pbv1.PayloadExMsg, stored *[]core.VersionedProposal) *PayloadEx {
		return &PayloadEx{
			peerIdx: peerIdx,
			peers:   peers,
			retentionFunc: func(core.Duty) (time.Time, bool) {
				return time.Now().Add(time.Minute), true
			},
			sendFunc: func(_ context.Context, _ host.Host, _ protocol.ID, _ peer.ID, msg proto.Message, _ ...p2p.SendRecvOption) error {
				pb, ok := msg.(*pbv1.PayloadExMsg)
				require.True(t, ok)

				sent <- pb

				return nil
			},
			awaitProposalFunc: func(context.Context, uint64) (core.VersionedProposal, error) {
				return agreed, nil
			},
			storeFunc: func(_ context.Context, contents core.VersionedProposal) error {
				*stored = append(*stored, contents)
				return nil
			},
			candidates: make(map[candidateKey]core.VersionedProposal),
		}
	}

	t.Run("proposer stores and pushes its candidate", func(t *testing.T) {
		var stored []core.VersionedProposal

		sent := make(chan *pbv1.PayloadExMsg, n)
		p := newPayloadEx(proposerIdx, agreed, sent, &stored)
		require.NoError(t, p.StoreCandidate(t.Context(), contents))

		require.NoError(t, p.exchange(t.Context(), duty))
		require.Equal(t, []core.VersionedProposal{contents}, stored)
		require.Len(t, sent, n-1)

		// The peers get the contents.
		require.Equal(t, newTestMsg(t, duty, contents), <-sent)
	})

	t.Run("builder bid needs no exchange", func(t *testing.T) {
		var stored []core.VersionedProposal

		sent := make(chan *pbv1.PayloadExMsg, n)
		p := newPayloadEx(proposerIdx, testutil.RandomGloasCoreVersionedEPBSProposal(), sent, &stored)
		require.NoError(t, p.StoreCandidate(t.Context(), contents))

		require.NoError(t, p.exchange(t.Context(), duty))
		require.Empty(t, stored)
		require.Empty(t, sent)
	})

	t.Run("expired duty", func(t *testing.T) {
		var stored []core.VersionedProposal

		sent := make(chan *pbv1.PayloadExMsg, n)
		p := newPayloadEx(1, agreed, sent, &stored)
		p.awaitProposalFunc = func(ctx context.Context, _ uint64) (core.VersionedProposal, error) {
			<-ctx.Done()
			return core.VersionedProposal{}, ctx.Err()
		}

		ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
		defer cancel()

		require.ErrorIs(t, p.exchange(ctx, duty), context.DeadlineExceeded)
		require.Empty(t, stored)
		require.Empty(t, sent)
	})
}

func TestReceive(t *testing.T) {
	const slot = 1

	duty := core.NewProposerDuty(slot)

	contents := testutil.RandomGloasCoreVersionedEPBSProposalWithPayload()
	contents.EPBS.GloasContents.Block.Slot = slot

	agreed, err := core.WithoutPayloadContents(contents)
	require.NoError(t, err)

	// The store accepts the contents the agreed proposal commits to only, like the DutyDB.
	newPayloadEx := func(stored *[]core.VersionedProposal) *PayloadEx {
		return &PayloadEx{
			awaitProposalFunc: func(context.Context, uint64) (core.VersionedProposal, error) {
				return agreed, nil
			},
			storeFunc: func(_ context.Context, contents core.VersionedProposal) error {
				roots, err := core.NewPayloadContentsRoots(contents)
				if err != nil {
					return err
				}

				if roots != agreed.PayloadContentsRoots {
					return errors.New("payload contents roots mismatch")
				}

				*stored = append(*stored, contents)

				return nil
			},
		}
	}

	t.Run("stored", func(t *testing.T) {
		var stored []core.VersionedProposal

		require.NoError(t, newPayloadEx(&stored).receive(t.Context(), newTestMsg(t, duty, contents)))
		require.Equal(t, []core.VersionedProposal{contents}, stored)
	})

	t.Run("contents of another block", func(t *testing.T) {
		var stored []core.VersionedProposal

		other := testutil.RandomGloasCoreVersionedEPBSProposalWithPayload()
		other.EPBS.GloasContents.Block.Slot = slot

		err := newPayloadEx(&stored).receive(t.Context(), newTestMsg(t, duty, other))
		require.ErrorContains(t, err, "roots mismatch")
		require.Empty(t, stored)
	})

	t.Run("contents of another slot", func(t *testing.T) {
		var stored []core.VersionedProposal

		err := newPayloadEx(&stored).receive(t.Context(), newTestMsg(t, core.NewProposerDuty(slot+1), contents))
		require.ErrorContains(t, err, "another slot")
		require.Empty(t, stored)
	})

	t.Run("not decided", func(t *testing.T) {
		var stored []core.VersionedProposal

		p := newPayloadEx(&stored)
		p.awaitProposalFunc = func(ctx context.Context, _ uint64) (core.VersionedProposal, error) {
			<-ctx.Done()
			return core.VersionedProposal{}, ctx.Err()
		}

		ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
		defer cancel()

		err := p.receive(ctx, newTestMsg(t, duty, contents))
		require.ErrorContains(t, err, "await agreed proposal")
		require.Empty(t, stored)
	})
}

func TestPull(t *testing.T) {
	const (
		n           = 3
		proposerIdx = 0
		slot        = 1
	)

	duty := core.NewProposerDuty(slot)
	peers := newTestPeers(t, n)

	contents := testutil.RandomGloasCoreVersionedEPBSProposalWithPayload()
	contents.EPBS.GloasContents.Block.Slot = slot

	root, err := contents.Root()
	require.NoError(t, err)

	// Valid contents of another retained slot.
	other := testutil.RandomGloasCoreVersionedEPBSProposalWithPayload()
	other.EPBS.GloasContents.Block.Slot = slot + 1

	var logBuf zaptest.Buffer
	log.InitLogfmtForT(t, &logBuf)

	// Every slot's proposal is agreed, the contents are not held, so the peers are asked.
	newPayloadEx := func(answers map[peer.ID]*pbv1.PayloadExMsg, stored *[]core.VersionedProposal) *PayloadEx {
		return &PayloadEx{
			peerIdx: proposerIdx,
			peers:   peers,
			awaitProposalFunc: func(context.Context, uint64) (core.VersionedProposal, error) {
				return core.VersionedProposal{}, nil
			},
			awaitContentsFunc: func(context.Context, uint64, eth2p0.Root) (*eth2api.VersionedEPBSProposal, error) {
				return nil, errors.New("not held")
			},
			storeFunc: func(_ context.Context, contents core.VersionedProposal) error {
				*stored = append(*stored, contents)
				return nil
			},
			sendReceiveFunc: func(_ context.Context, _ host.Host, peerID peer.ID, _, resp proto.Message, _ protocol.ID, _ ...p2p.SendRecvOption) error {
				answer, ok := answers[peerID]
				if !ok {
					return errors.New("no answer")
				}

				proto.Merge(resp, answer)

				return nil
			},
		}
	}

	t.Run("answer for another slot", func(t *testing.T) {
		var stored []core.VersionedProposal

		logBuf.Reset()

		p := newPayloadEx(map[peer.ID]*pbv1.PayloadExMsg{
			peers[1]: newTestMsg(t, core.NewProposerDuty(slot+1), other),
			peers[2]: newTestMsg(t, core.NewProposerDuty(slot+1), other),
		}, &stored)

		p.pull(t.Context(), duty, root)
		require.Empty(t, stored)
		require.Contains(t, logBuf.String(), "another duty")
		require.Contains(t, logBuf.String(), "not received from any peer")
	})

	t.Run("answer for the slot", func(t *testing.T) {
		var stored []core.VersionedProposal

		logBuf.Reset()

		p := newPayloadEx(map[peer.ID]*pbv1.PayloadExMsg{
			peers[1]: newTestMsg(t, core.NewProposerDuty(slot+1), other),
			peers[2]: newTestMsg(t, duty, contents),
		}, &stored)

		p.pull(t.Context(), duty, root)
		require.Equal(t, []core.VersionedProposal{contents}, stored)
		require.NotContains(t, logBuf.String(), "not received from any peer")
	})
}

func TestHandle(t *testing.T) {
	const slot = 1

	duty := core.NewProposerDuty(slot)
	peers := newTestPeers(t, 2)

	contents := testutil.RandomGloasCoreVersionedEPBSProposalWithPayload()
	contents.EPBS.GloasContents.Block.Slot = slot

	agreed, err := core.WithoutPayloadContents(contents)
	require.NoError(t, err)

	decided := make(chan struct{})
	stored := make(chan core.VersionedProposal, 8)

	// Pushes are held until the decision, bounded by the duty deadline.
	p := &PayloadEx{
		peers:     peers,
		gaterFunc: func(core.Duty) bool { return true },
		retentionFunc: func(core.Duty) (time.Time, bool) {
			return time.Now().Add(time.Second), true
		},
		awaitProposalFunc: func(ctx context.Context, _ uint64) (core.VersionedProposal, error) {
			select {
			case <-decided:
				return agreed, nil
			case <-ctx.Done():
				return core.VersionedProposal{}, ctx.Err()
			}
		},
		storeFunc: func(_ context.Context, contents core.VersionedProposal) error {
			stored <- contents
			return nil
		},
	}

	pending := func(peerID peer.ID) bool {
		p.pendingPushes.mu.Lock()
		defer p.pendingPushes.mu.Unlock()

		_, ok := p.pendingPushes.slots[peerID]

		return ok
	}

	msg := newTestMsg(t, duty, contents)

	_, _, err = p.handle(t.Context(), peers[1], msg)
	require.NoError(t, err)
	require.True(t, pending(peers[1]))

	// A peer has one push held at a time, for this or any other slot.
	_, _, err = p.handle(t.Context(), peers[1], msg)
	require.ErrorContains(t, err, "already pending")

	_, _, err = p.handle(t.Context(), peers[1], newTestMsg(t, core.NewProposerDuty(slot+1), contents))
	require.ErrorContains(t, err, "already pending")

	// Other duties and unknown peers are rejected.
	_, _, err = p.handle(t.Context(), peers[1], newTestMsg(t, core.NewAttesterDuty(slot), contents))
	require.ErrorContains(t, err, "invalid payloadex duty")

	_, _, err = p.handle(t.Context(), peer.ID("unknown"), msg)
	require.ErrorContains(t, err, "unknown peer")

	// The decision releases the held push: the contents are stored and nothing stays pending.
	close(decided)

	require.Equal(t, contents, <-stored)
	require.Eventually(t, func() bool { return !pending(peers[1]) }, time.Second, 5*time.Millisecond)
	require.Empty(t, stored)
}

func TestHandleRequest(t *testing.T) {
	const slot = 1

	duty := core.NewProposerDuty(slot)
	peers := newTestPeers(t, 2)

	contents := testutil.RandomGloasCoreVersionedEPBSProposalWithPayload()
	contents.EPBS.GloasContents.Block.Slot = slot

	root, err := contents.Root()
	require.NoError(t, err)

	// The DutyDB serves the contents of the agreed block only, the others wait until the duty
	// deadline at most.
	p := &PayloadEx{
		peers:     peers,
		gaterFunc: func(core.Duty) bool { return true },
		retentionFunc: func(core.Duty) (time.Time, bool) {
			return time.Now().Add(time.Minute), true
		},
		awaitContentsFunc: func(ctx context.Context, s uint64, r eth2p0.Root) (*eth2api.VersionedEPBSProposal, error) {
			if s == slot && r == eth2p0.Root(root) {
				return contents.EPBS, nil
			}

			<-ctx.Done()

			return nil, ctx.Err()
		},
	}

	request := func(duty core.Duty, root eth2p0.Root) *pbv1.PayloadExRequest {
		return &pbv1.PayloadExRequest{Duty: core.DutyToProto(duty), BlockRoot: root[:]}
	}

	// Held contents are served from the DutyDB.
	resp, ok, err := p.handleRequest(t.Context(), peers[1], request(duty, root))
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, newTestMsg(t, duty, contents), resp)

	// Contents not held within the request timeout aren't answered.
	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()

	_, ok, err = p.handleRequest(ctx, peers[1], request(duty, testutil.RandomRoot()))
	require.NoError(t, err)
	require.False(t, ok)

	// Nor past the duty deadline.
	p.retentionFunc = func(core.Duty) (time.Time, bool) {
		return time.Now().Add(20 * time.Millisecond), true
	}

	_, ok, err = p.handleRequest(t.Context(), peers[1], request(duty, testutil.RandomRoot()))
	require.NoError(t, err)
	require.False(t, ok)

	p.retentionFunc = func(core.Duty) (time.Time, bool) {
		return time.Now().Add(time.Minute), true
	}

	// A peer has one request held at a time, for this or any other slot.
	pending := func(peerID peer.ID) bool {
		p.pendingRequests.mu.Lock()
		defer p.pendingRequests.mu.Unlock()

		_, ok := p.pendingRequests.slots[peerID]

		return ok
	}

	parkedCtx, parkedCancel := context.WithCancel(t.Context())
	defer parkedCancel()

	go func() {
		_, _, _ = p.handleRequest(parkedCtx, peers[1], request(core.NewProposerDuty(slot+1), testutil.RandomRoot()))
	}()

	require.Eventually(t, func() bool { return pending(peers[1]) }, time.Second, 5*time.Millisecond)

	_, _, err = p.handleRequest(t.Context(), peers[1], request(core.NewProposerDuty(slot+1), testutil.RandomRoot()))
	require.ErrorContains(t, err, "already pending")

	_, _, err = p.handleRequest(t.Context(), peers[1], request(core.NewProposerDuty(slot+2), testutil.RandomRoot()))
	require.ErrorContains(t, err, "already pending")

	parkedCancel()
	require.Eventually(t, func() bool { return !pending(peers[1]) }, time.Second, 5*time.Millisecond)

	// Requests of other duties and from unknown peers are rejected.
	_, _, err = p.handleRequest(t.Context(), peers[1], request(core.NewAttesterDuty(slot), root))
	require.ErrorContains(t, err, "invalid payloadex request duty")

	_, _, err = p.handleRequest(t.Context(), peer.ID("unknown"), request(duty, root))
	require.ErrorContains(t, err, "unknown peer")
}

// newTestPeers returns the peer IDs of n insecure test keys.
func newTestPeers(t *testing.T, n int) []peer.ID {
	t.Helper()

	var peers []peer.ID

	for i := range n {
		peerID, err := p2p.PeerIDFromKey(testutil.GenerateInsecureK1Key(t, i).PubKey())
		require.NoError(t, err)

		peers = append(peers, peerID)
	}

	return peers
}

// newTestMsg returns the message carrying the contents of the duty.
func newTestMsg(t *testing.T, duty core.Duty, contents core.VersionedProposal) *pbv1.PayloadExMsg {
	t.Helper()

	msg, err := newMsg(duty, contents)
	require.NoError(t, err)

	return msg
}
