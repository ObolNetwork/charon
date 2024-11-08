// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import (
	"context"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/tbls"
)

// Replica represents a single HotStuff replica.
// A replica can also serve as the leader depending on the view.
type Replica struct {
	// Immutable state
	id           ID
	cluster      *Cluster
	transport    Transport[Msg]
	recvCh       <-chan Msg
	phaseTimeout time.Duration

	// Mutable state
	view        View
	phase       Phase
	leaderPhase Phase
	prepareQC   *QC
	lockedQC    *QC
	collector   *Collector
}

func NewReplica(id ID, cluster *Cluster, transport Transport[Msg], phaseTimeout time.Duration) (*Replica, error) {
	recvCh, err := transport.ReceiveCh(id)
	if err != nil {
		return nil, err
	}

	return &Replica{
		id:           id,
		cluster:      cluster,
		transport:    transport,
		recvCh:       recvCh,
		phaseTimeout: phaseTimeout,
		view:         1,
		phase:        PreparePhase,
		leaderPhase:  PreparePhase,
		collector:    NewCollector(),
	}, nil
}

func (p *Replica) Run(ctx context.Context, done func()) {
	ctx = log.WithCtx(log.WithTopic(ctx, "hotstuff"), z.Uint("replica", uint(p.id)))

	defer func() {
		log.Debug(ctx, "Stopped")
		done()
	}()

	log.Debug(ctx, "Starting")

	// Initially all replicas send a NewView message to the leader.
	if err := p.sendNewView(ctx); err != nil {
		log.Error(ctx, "Failed to send new_view", err)
	}

	for {
		select {
		case msg, ok := <-p.recvCh:
			if !ok {
				return
			}
			p.handleMsg(ctx, msg)
		case <-ctx.Done():
			return
		case <-time.After(p.phaseTimeout):
			log.Warn(ctx, "Phase timeout", nil)
			if err := p.nextView(ctx); err != nil {
				log.Error(ctx, "Failed to move to next view", err)
			}
		}
	}
}

func (p *Replica) handleMsg(ctx context.Context, msg Msg) {
	ctx = log.WithCtx(ctx,
		z.U64("sender", uint64(msg.Sender)),
		z.U64("view", uint64(p.view)),
		z.Str("phase", p.phase.String()))

	leader := p.cluster.Leader(p.view)

	log.Debug(ctx, "Processing message "+msg.Type.String(), z.U64("leader", uint64(leader)))

	// NewView message has special handling
	if msg.Type == MsgNewView {
		if leader != p.id {
			log.Debug(ctx, "NewView message ignored due to wrong leader")
		} else {
			p.leaderNewView(ctx, msg)
		}

		return
	}

	if msg.View != p.view {
		log.Debug(ctx, "Message ignored due to wrong view")
		return
	}

	if leader == p.id && msg.Vote {
		p.leaderDuty(ctx, msg)
	}

	if !msg.Vote {
		p.replicaDuty(ctx, msg, leader)
	}
}

func (p *Replica) leaderDuty(ctx context.Context, msg Msg) {
	validLeaderMsgInPhase := map[Phase]MsgType{
		PreparePhase:   MsgPrepare,
		PreCommitPhase: MsgPrepare,
		CommitPhase:    MsgPreCommit,
		DecidePhase:    MsgCommit,
	}

	if t, ok := validLeaderMsgInPhase[p.leaderPhase]; !ok || msg.Type != t {
		return
	}

	p.collector.AddMsg(&msg)
	mm := p.collector.MatchingMsg(MsgPrepare, p.view)
	if len(mm) < int(p.cluster.threshold) {
		return
	}

	qc, err := createQC(mm)
	if err != nil {
		log.Error(ctx, "Failed to construct qc", err)
		return
	}
	if err := qc.Verify(p.cluster.publicKey); err != nil {
		log.Error(ctx, "Failed to verify qc", err)
		return
	}

	p.leaderPhase = p.leaderPhase.NextPhase()

	t := msg.Type.NextMsgType()
	err = p.transport.Broadcast(ctx, Msg{
		Sender:  p.id,
		Type:    t,
		View:    p.view,
		Justify: qc,
	})
	if err != nil {
		log.Error(ctx, "Leader failed to broadcast", err)
	}
}

func (p *Replica) leaderNewView(ctx context.Context, msg Msg) {
	if p.leaderPhase != PreparePhase || msg.Type != MsgNewView {
		return
	}

	p.collector.AddMsg(&msg)
	mm := p.collector.MatchingMsg(MsgNewView, p.view-1)
	if len(mm) < int(p.cluster.threshold) {
		return
	}

	// HighQC will be nil in the first view
	highQC := selectHighQC(mm)
	if err := highQC.Verify(p.cluster.publicKey); err != nil {
		log.Error(ctx, "Failed to verify qc", err)
		return
	}

	p.leaderPhase = p.leaderPhase.NextPhase()

	newValue := <-p.cluster.inputCh
	err := p.transport.Broadcast(ctx, Msg{
		Sender:  p.id,
		Type:    MsgPrepare,
		View:    p.view,
		Value:   newValue,
		Justify: highQC,
	})
	if err != nil {
		log.Error(ctx, "Failed to broadcast prepare", err)
	}
}

func (p *Replica) sendNewView(ctx context.Context) error {
	nextLeader := p.cluster.Leader(p.view)

	return p.transport.SendTo(ctx, nextLeader, Msg{
		Sender:  p.id,
		Type:    MsgNewView,
		View:    p.view - 1,
		Justify: p.prepareQC,
	})
}

func (p *Replica) nextView(ctx context.Context) error {
	p.view++
	p.phase = PreparePhase
	p.leaderPhase = PreparePhase
	p.prepareQC = nil
	p.lockedQC = nil

	return p.sendNewView(ctx)
}

func (p *Replica) replicaDuty(ctx context.Context, msg Msg, leader ID) {
	currentPhase := p.phase
	p.phase = p.phase.NextPhase()

	switch currentPhase {
	case PreparePhase:
		if !p.safeNode(msg.Justify) {
			log.Error(ctx, "Unsafe node", nil)
		} else {
			p.sendVote(ctx, MsgPrepare, msg.Value, leader)
		}
	case PreCommitPhase:
		p.prepareQC = msg.Justify
		p.sendVote(ctx, MsgPreCommit, msg.Value, leader)
	case CommitPhase:
		p.lockedQC = msg.Justify
		p.sendVote(ctx, MsgCommit, msg.Justify.Value, leader)
	case DecidePhase:
		log.Info(ctx, "Decided value", z.Str("value", msg.Justify.Value))
		p.cluster.outputCh <- msg.Justify.Value
	default:
		log.Debug(ctx, "Ignoring message in terminal phase")
	}
}

func (p *Replica) safeNode(qc *QC) bool {
	if qc == nil {
		// Initial view has no justification
		return true
	}

	if p.lockedQC == nil {
		return true
	}

	// Liveness rule
	return qc.View > p.lockedQC.View
}

func (p *Replica) sendVote(ctx context.Context, t MsgType, value string, leader ID) {
	voteMsg := Msg{
		Sender: p.id,
		Type:   t,
		View:   p.view,
		Value:  value,
		Vote:   true,
	}

	privKey := p.cluster.privateKeys[p.id]
	sig, err := Sign(privKey, t, p.view, value)
	if err != nil {
		log.Error(ctx, "Failed to sign vote", err)
		return
	}

	voteMsg.ParSig = sig

	if err := p.transport.SendTo(ctx, leader, voteMsg); err != nil {
		log.Error(ctx, "Failed to send vote", err)
	}
}

func selectHighQC(msgs []*Msg) *QC {
	highQC := msgs[0].Justify

	for _, msg := range msgs[1:] {
		if msg.Justify != nil && (highQC == nil || msg.Justify.View > highQC.View) {
			highQC = msg.Justify
		}
	}

	return highQC
}

func createQC(msgs []*Msg) (*QC, error) {
	parSigs := make(map[int]tbls.Signature)

	for _, msg := range msgs {
		parSigs[int(msg.Sender)] = tbls.Signature(msg.ParSig)
	}

	aggSig, err := tbls.ThresholdAggregate(parSigs)
	if err != nil {
		return nil, errors.Wrap(err, "aggregate sig")
	}

	return &QC{
		Type:  msgs[0].Type,
		View:  msgs[0].View,
		Value: msgs[0].Value,
		Sig:   aggSig[:],
	}, nil
}
