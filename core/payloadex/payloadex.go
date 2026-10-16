// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package payloadex exchanges the execution payload envelope, blobs and KZG proofs of an agreed
// self-built gloas proposal between the node that built it and its peers. Consensus agrees on the
// beacon block and the root of its payload contents only, so that the large contents don't travel
// with every consensus message. Each node holds the contents of the block it proposes as its
// candidate; once a block is agreed, the node whose candidate it is pushes the contents, and a peer
// that didn't receive them, e.g. because its link to the proposer is broken, pulls them from the
// peers that did. The DutyDB is the only store of the agreed contents: received contents go into
// it, which accepts those hashing to the agreed root only, whoever delivers them, and pulls are
// answered from it. The exchange lives as long as the DutyDB retains the agreed proposal, until the
// end of the slot, see core.NewDutyRetentionFunc.
package payloadex

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/p2p"
)

const (
	// protocolID1 carries the contents pushed by the proposer.
	protocolID1 = "/charon/payloadex/1.0.0"
	// requestProtocolID1 carries the requests of peers that didn't receive the contents, answered
	// with the contents once the peer holds them.
	requestProtocolID1 = "/charon/payloadex/request/1.0.0"

	// maxMsgSize caps the size of received contents: a self-built proposal with its blobs,
	// at most a few MB, like consensus messages carried before this protocol.
	maxMsgSize = 32 * 1024 * 1024 // 32 MB.

	// pullDelay is how long after the local decision a node waits for the proposer's push before
	// asking its peers for the contents, a few times the usual transfer.
	pullDelay = time.Second

	// requestTimeout is how long a request for the contents stays open, on both sides: a peer
	// answers as soon as it holds the contents, so a request is also a subscription to a push
	// that reaches the peer later. The duty deadline bounds it on the requester's side.
	requestTimeout = 12 * time.Second
)

// Protocols returns the supported protocols of this package in order of precedence.
func Protocols() []protocol.ID {
	return []protocol.ID{protocolID1, requestProtocolID1}
}

// New returns a new payload exchange component and registers its libp2p handlers. The retention
// function bounds the exchange of a slot's contents like the DutyDB retains its agreed proposal.
// The DutyDB functions it depends on are registered with the Register methods before use.
func New(p2pNode host.Host, sendFunc p2p.SendFunc, sendReceiveFunc p2p.SendReceiveFunc, peerIdx int,
	peers []p2p.Peer, gaterFunc core.DutyGaterFunc, retentionFunc core.DeadlineFunc,
) *PayloadEx {
	var peerIDs []peer.ID
	for _, p := range peers {
		peerIDs = append(peerIDs, p.ID)
	}

	p := &PayloadEx{
		p2pNode:         p2pNode,
		sendFunc:        sendFunc,
		sendReceiveFunc: sendReceiveFunc,
		peerIdx:         peerIdx,
		peers:           peerIDs,
		gaterFunc:       gaterFunc,
		retentionFunc:   retentionFunc,
		candidates:      make(map[uint64]candidate),
	}

	p2p.RegisterHandler("payloadex", p2pNode, protocolID1,
		func() proto.Message { return new(pbv1.PayloadExMsg) },
		p.handle, p2p.WithReadLimit(maxMsgSize))

	p2p.RegisterHandler("payloadex", p2pNode, requestProtocolID1,
		func() proto.Message { return new(pbv1.PayloadExRequest) },
		p.handleRequest, p2p.WithReceiveTimeout(requestTimeout))

	return p
}

// PayloadEx exchanges the execution payload contents of agreed self-built proposals.
type PayloadEx struct {
	p2pNode         host.Host
	sendFunc        p2p.SendFunc
	sendReceiveFunc p2p.SendReceiveFunc
	peerIdx         int
	peers           []peer.ID
	gaterFunc       core.DutyGaterFunc
	retentionFunc   core.DeadlineFunc // Until when the agreed proposal of a duty is retained, bounding its exchange.

	awaitProposalFunc func(ctx context.Context, slot uint64) (core.VersionedProposal, error)
	awaitContentsFunc func(ctx context.Context, slot uint64, root eth2p0.Root) (*eth2api.VersionedEPBSProposal, error)
	storeFunc         func(context.Context, core.VersionedProposal) error

	mu         sync.Mutex
	candidates map[uint64]candidate // This node's candidate contents by slot, those of the self-built block it proposes.

	pendingPushes   pendingSet // Pushes held until the decision, by peer.
	pendingRequests pendingSet // Requests held until the contents are held, by peer.
}

// candidate is this node's candidate execution payload contents of a slot, with their root.
type candidate struct {
	root     [32]byte
	contents core.VersionedProposal
}

// RegisterAwaitVersionedProposal registers the DutyDB function to await agreed proposals by slot.
func (p *PayloadEx) RegisterAwaitVersionedProposal(fn func(ctx context.Context, slot uint64) (core.VersionedProposal, error)) {
	p.awaitProposalFunc = fn
}

// RegisterAwaitPayloadContents registers the DutyDB function to await the agreed execution payload contents.
func (p *PayloadEx) RegisterAwaitPayloadContents(fn func(ctx context.Context, slot uint64, root eth2p0.Root) (*eth2api.VersionedEPBSProposal, error)) {
	p.awaitContentsFunc = fn
}

// RegisterStorePayloadContents registers the DutyDB function to store the agreed execution payload contents.
func (p *PayloadEx) RegisterStorePayloadContents(fn func(context.Context, core.VersionedProposal) error) {
	p.storeFunc = fn
}

// StoreCandidate holds this node's candidate execution payload contents, those of the self-built
// block it proposes, until the proposer duty deadline, to share them if the block is agreed. It is
// subscribed to the fetcher's payload contents.
func (p *PayloadEx) StoreCandidate(_ context.Context, contents core.VersionedProposal) error {
	root, err := core.PayloadContentsRoot(contents)
	if err != nil {
		return err
	}

	slot, err := contents.Slot()
	if err != nil {
		return err
	}

	duty := core.NewProposerDuty(uint64(slot))

	deadline, ok := p.retentionFunc(duty)
	if !ok {
		return errors.New("payloadex duty without retention", z.Any("duty", duty))
	}

	clone, err := contents.Clone() // Clone before storing.
	if err != nil {
		return err
	}

	cloned, ok := clone.(core.VersionedProposal)
	if !ok {
		return errors.New("invalid versioned proposal")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// The fetcher proposes one block per slot.
	_, exists := p.candidates[duty.Slot]
	if exists {
		return errors.New("candidate execution payload contents already stored", z.Any("duty", duty))
	}

	p.candidates[duty.Slot] = candidate{root: root, contents: cloned}

	time.AfterFunc(time.Until(deadline), func() {
		p.mu.Lock()
		defer p.mu.Unlock()

		delete(p.candidates, duty.Slot)
	})

	return nil
}

// candidate returns this node's candidate contents of the slot, if any.
func (p *PayloadEx) candidate(slot uint64) (candidate, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	cand, ok := p.candidates[slot]

	return cand, ok
}

// Exchange arranges the exchange of the execution payload contents of the duty's agreed proposal,
// if it is a self-built gloas block: once agreed, this node stores and pushes the contents to all
// peers if they are its candidate, i.e. it built the block, or pulls them from the peers if the
// proposer's push doesn't arrive. It is subscribed to the scheduler's duties and returns without
// waiting.
func (p *PayloadEx) Exchange(ctx context.Context, duty core.Duty, _ core.DutyDefinitionSet) error {
	if duty.Type != core.DutyProposer {
		return nil
	}

	deadline, ok := p.retentionFunc(duty)
	if !ok {
		return errors.New("payloadex duty without retention", z.Any("duty", duty))
	}

	// The scheduler's context ends with the slot, the exchange lives until the duty deadline.
	ctx, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	ctx = log.WithTopic(log.WithCtx(ctx, z.Any("duty", duty)), "payloadex")

	go func() {
		defer cancel()

		err := p.exchange(ctx, duty)
		if err != nil && ctx.Err() == nil { // The duty expiring without a decision is not an exchange failure.
			log.Warn(ctx, "Execution payload contents exchange failed", err)
		}
	}()

	return nil
}

// exchange awaits the agreed proposal and pushes or pulls its contents, see Exchange.
func (p *PayloadEx) exchange(ctx context.Context, duty core.Duty) error {
	agreed, err := p.awaitProposalFunc(ctx, duty.Slot)
	if err != nil {
		return errors.Wrap(err, "await agreed proposal")
	}

	// Only self-built gloas blocks are agreed without their contents, committed to by their root.
	if agreed.Version < eth2spec.DataVersionGloas || agreed.PayloadContentsRoot == [32]byte{} {
		return nil
	}

	root, err := agreed.Root()
	if err != nil {
		return err
	}

	// This node built the agreed block if its candidate contents are those the block commits to.
	cand, ok := p.candidate(duty.Slot)
	if ok && cand.root == agreed.PayloadContentsRoot {
		return p.push(ctx, duty, cand.contents)
	}

	p.pull(ctx, duty, root)

	return nil
}

// push stores this node's own contents of the agreed block and sends them to all peers.
func (p *PayloadEx) push(ctx context.Context, duty core.Duty, contents core.VersionedProposal) error {
	err := p.storeFunc(ctx, contents)
	if err != nil {
		return errors.Wrap(err, "store execution payload contents")
	}

	msg, err := newMsg(duty, contents)
	if err != nil {
		return err
	}

	for i, peerID := range p.peers {
		if i == p.peerIdx {
			continue
		}

		err := p.sendFunc(ctx, p.p2pNode, protocolID1, peerID, msg, p2p.WithSendMetricTopic("payloadex"))
		if err != nil {
			return err
		}
	}

	sharedCounter.Inc()
	log.Debug(ctx, "Shared execution payload contents of agreed self-built proposal")

	return nil
}

// pull awaits the contents of the agreed block for the pull delay and, if the proposer's push
// hasn't arrived by then, asks all peers for them once, accepting the first valid answer.
func (p *PayloadEx) pull(ctx context.Context, duty core.Duty, root eth2p0.Root) {
	awaitCtx, cancel := context.WithTimeout(ctx, pullDelay)
	_, err := p.awaitContentsFunc(awaitCtx, duty.Slot, root)

	cancel()

	if err == nil || ctx.Err() != nil {
		return // The push arrived, or the duty expired.
	}

	// The proposer's push should have arrived by now, pulling is the fallback.
	requestedCounter.Inc()
	log.Warn(ctx, "Execution payload contents of agreed self-built proposal not received from the proposer, requesting them from peers", nil)

	// The first accepted answer cancels the other requests.
	ctx, cancel = context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	req := &pbv1.PayloadExRequest{
		Duty:      core.DutyToProto(duty),
		BlockRoot: root[:],
	}

	var (
		wg       sync.WaitGroup
		accepted atomic.Bool
	)

	for i, peerID := range p.peers {
		if i == p.peerIdx {
			continue
		}

		wg.Go(func() {
			resp := new(pbv1.PayloadExMsg)

			err := p.sendReceiveFunc(ctx, p.p2pNode, peerID, req, resp, requestProtocolID1,
				p2p.WithReadLimit(maxMsgSize), p2p.WithSendTimeout(requestTimeout))
			if err != nil {
				if ctx.Err() == nil {
					log.Debug(ctx, "Execution payload contents request failed", z.Err(err), z.Str("peer", p2p.PeerName(peerID)))
				}

				return
			}

			err = p.receive(ctx, resp)
			if err != nil {
				if ctx.Err() == nil {
					receivedCounter.WithLabelValues("rejected").Inc()
					log.Warn(ctx, "Rejected requested execution payload contents", err, z.Str("peer", p2p.PeerName(peerID)))
				}

				return
			}

			receivedCounter.WithLabelValues("accepted").Inc()
			log.Debug(ctx, "Accepted requested execution payload contents", z.Str("peer", p2p.PeerName(peerID)))
			accepted.Store(true)
			cancel()
		})
	}

	wg.Wait()

	if !accepted.Load() {
		log.Warn(ctx, "Execution payload contents of agreed self-built proposal not received from any peer, the payload will not be revealed", nil)
	}
}

// handle receives pushed execution payload contents and stores them asynchronously, since the
// decision may still be in flight on this node, holding one push per peer.
func (p *PayloadEx) handle(ctx context.Context, sender peer.ID, req proto.Message) (proto.Message, bool, error) {
	pb, ok := req.(*pbv1.PayloadExMsg)
	if !ok || pb == nil || pb.GetDuty() == nil || len(pb.GetContents()) == 0 {
		return nil, false, errors.New("invalid payloadex message")
	}

	duty := core.DutyFromProto(pb.GetDuty())
	if duty.Type != core.DutyProposer || !p.gaterFunc(duty) {
		return nil, false, errors.New("invalid payloadex duty", z.Any("duty", duty))
	}

	if !slices.Contains(p.peers, sender) {
		return nil, false, errors.New("payloadex message from unknown peer")
	}

	deadline, ok := p.retentionFunc(duty)
	if !ok {
		return nil, false, errors.New("payloadex duty without retention", z.Any("duty", duty))
	}

	err := p.pendingPushes.add(sender, duty.Slot)
	if err != nil {
		return nil, false, errors.Wrap(err, "payloadex push", z.Any("duty", duty), z.Str("peer", p2p.PeerName(sender)))
	}

	// The handler's context ends when it returns, the acceptance lives until the duty deadline.
	ctx, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)

	go func() {
		defer cancel()
		defer p.pendingPushes.remove(sender, duty.Slot)

		ctx := log.WithCtx(ctx, z.Any("duty", duty))

		err := p.receive(ctx, pb)
		if err != nil {
			receivedCounter.WithLabelValues("rejected").Inc()
			log.Warn(ctx, "Rejected shared execution payload contents", err)

			return
		}

		receivedCounter.WithLabelValues("accepted").Inc()
		log.Debug(ctx, "Accepted shared execution payload contents")
	}()

	return nil, false, nil
}

// handleRequest answers a peer's request with the agreed contents it asks for, from the DutyDB,
// once held, within the request timeout and the duty deadline, holding one request per peer.
func (p *PayloadEx) handleRequest(ctx context.Context, sender peer.ID, req proto.Message) (proto.Message, bool, error) {
	pb, ok := req.(*pbv1.PayloadExRequest)
	if !ok || pb == nil || pb.GetDuty() == nil || len(pb.GetBlockRoot()) != len(eth2p0.Root{}) {
		return nil, false, errors.New("invalid payloadex request")
	}

	duty := core.DutyFromProto(pb.GetDuty())
	if duty.Type != core.DutyProposer || !p.gaterFunc(duty) {
		return nil, false, errors.New("invalid payloadex request duty", z.Any("duty", duty))
	}

	if !slices.Contains(p.peers, sender) {
		return nil, false, errors.New("payloadex request from unknown peer")
	}

	err := p.pendingRequests.add(sender, duty.Slot)
	if err != nil {
		return nil, false, errors.Wrap(err, "payloadex request", z.Any("duty", duty), z.Str("peer", p2p.PeerName(sender)))
	}

	defer p.pendingRequests.remove(sender, duty.Slot)

	deadline, ok := p.retentionFunc(duty)
	if !ok {
		return nil, false, errors.New("payloadex duty without retention", z.Any("duty", duty))
	}

	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	epbs, err := p.awaitContentsFunc(ctx, duty.Slot, eth2p0.Root(pb.GetBlockRoot()))
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		servedCounter.WithLabelValues("missing").Inc()

		return nil, false, nil // Not held within the request timeout, no answer.
	} else if err != nil {
		return nil, false, errors.Wrap(err, "await execution payload contents")
	}

	contents, err := core.NewVersionedEPBSProposal(epbs)
	if err != nil {
		return nil, false, err
	}

	msg, err := newMsg(duty, contents)
	if err != nil {
		return nil, false, err
	}

	servedCounter.WithLabelValues("found").Inc()

	return msg, true, nil
}

// receive stores the received contents once the proposal of their slot is agreed, which the
// store verifies them against.
func (p *PayloadEx) receive(ctx context.Context, pb *pbv1.PayloadExMsg) error {
	if pb.GetDuty() == nil || len(pb.GetContents()) == 0 {
		return errors.New("invalid payloadex message")
	}

	duty := core.DutyFromProto(pb.GetDuty())
	if duty.Type != core.DutyProposer {
		return errors.New("invalid payloadex duty", z.Any("duty", duty))
	}

	// Decode once decided, so that a push held for the decision costs its bytes only.
	_, err := p.awaitProposalFunc(ctx, duty.Slot)
	if err != nil {
		return errors.Wrap(err, "await agreed proposal")
	}

	var contents core.VersionedProposal

	err = contents.UnmarshalSSZ(pb.GetContents())
	if err != nil {
		return errors.Wrap(err, "decode payloadex contents")
	}

	slot, err := contents.Slot()
	if err != nil {
		return err
	}

	if uint64(slot) != duty.Slot {
		return errors.New("payloadex contents of another slot", z.U64("slot", uint64(slot)))
	}

	err = p.storeFunc(ctx, contents)
	if err != nil {
		return errors.Wrap(err, "store execution payload contents")
	}

	return nil
}

// pendingSet holds the slot each peer has work pending for, one at a time: a peer pushes and
// requests once per slot and each lives at most until the end of its slot, so more is a bug or
// abuse, and the first push or request from a peer is the one held.
type pendingSet struct {
	mu    sync.Mutex
	slots map[peer.ID]uint64
}

// add registers the peer's pending slot, or errors if the peer already has one pending.
func (s *pendingSet) add(peerID peer.ID, slot uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.slots == nil {
		s.slots = make(map[peer.ID]uint64)
	}

	pending, ok := s.slots[peerID]
	if ok {
		return errors.New("already pending", z.U64("pending_slot", pending))
	}

	s.slots[peerID] = slot

	return nil
}

// remove unregisters the peer's pending slot.
func (s *pendingSet) remove(peerID peer.ID, slot uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.slots[peerID] == slot {
		delete(s.slots, peerID)
	}
}

// newMsg returns the message carrying the contents of the duty.
func newMsg(duty core.Duty, contents core.VersionedProposal) (*pbv1.PayloadExMsg, error) {
	b, err := contents.MarshalSSZ()
	if err != nil {
		return nil, errors.Wrap(err, "encode payloadex contents")
	}

	return &pbv1.PayloadExMsg{
		Duty:     core.DutyToProto(duty),
		Contents: b,
	}, nil
}
