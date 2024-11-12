// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import (
	"context"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
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

func (r *Replica) Run(ctx context.Context, done func()) {
	ctx = log.WithCtx(log.WithTopic(ctx, "hotstuff"), z.Uint("replica", uint(r.id)))

	defer func() {
		log.Debug(ctx, "Stopped")
		done()
	}()

	log.Debug(ctx, "Starting")

	// Initially all replicas send a NewView message to the leader.
	if err := r.sendNewView(ctx); err != nil {
		log.Error(ctx, "Failed to send new_view", err)
	}

	for {
		select {
		case msg, ok := <-r.recvCh:
			if !ok {
				return
			}
			r.handleMsg(ctx, msg)
		case <-ctx.Done():
			return
		case <-time.After(r.phaseTimeout):
			log.Warn(ctx, "Phase timeout", nil)
			if err := r.nextView(ctx); err != nil {
				log.Error(ctx, "Failed to move to next view", err)
			}
		}
	}
}

func (r *Replica) handleMsg(ctx context.Context, msg Msg) {
	ctx = log.WithCtx(ctx,
		z.U64("sender", uint64(msg.Sender)),
		z.U64("view", uint64(r.view)),
		z.Str("phase", r.phase.String()))

	leader := r.cluster.Leader(r.view)

	log.Debug(ctx, "Processing message "+msg.Type.String(), z.U64("leader", uint64(leader)))

	// NewView message has special handling
	if msg.Type == MsgNewView {
		if leader != r.id {
			log.Debug(ctx, "NewView message ignored due to wrong leader")
		} else {
			r.leaderNewView(ctx, msg)
		}

		return
	}

	if msg.View != r.view {
		log.Debug(ctx, "Message ignored due to wrong view")
		return
	}

	if leader == r.id && msg.Vote {
		r.leaderDuty(ctx, msg)
	}

	if !msg.Vote {
		r.replicaDuty(ctx, msg, leader)
	}
}

func (r *Replica) leaderDuty(ctx context.Context, msg Msg) {
	validLeaderMsgInPhase := map[Phase]MsgType{
		PreparePhase:   MsgPrepare,
		PreCommitPhase: MsgPrepare,
		CommitPhase:    MsgPreCommit,
		DecidePhase:    MsgCommit,
	}

	if t, ok := validLeaderMsgInPhase[r.leaderPhase]; !ok || msg.Type != t {
		return
	}

	r.collector.AddMsg(&msg)
	mm := r.collector.MatchingMsg(MsgPrepare, r.view)
	if len(mm) < int(r.cluster.threshold) {
		return
	}

	qc := createQC(mm)
	if err := r.verifyQC(qc); err != nil {
		log.Error(ctx, "Failed to verify qc", err)
		return
	}

	r.leaderPhase = r.leaderPhase.NextPhase()

	t := msg.Type.NextMsgType()
	err := r.transport.Broadcast(ctx, Msg{
		Sender:  r.id,
		Type:    t,
		View:    r.view,
		Justify: qc,
	})
	if err != nil {
		log.Error(ctx, "Leader failed to broadcast", err)
	}
}

func (r *Replica) leaderNewView(ctx context.Context, msg Msg) {
	if r.leaderPhase != PreparePhase || msg.Type != MsgNewView {
		return
	}

	r.collector.AddMsg(&msg)
	mm := r.collector.MatchingMsg(MsgNewView, r.view-1)
	if len(mm) < int(r.cluster.threshold) {
		return
	}

	// HighQC will be nil in the first view
	highQC := selectHighQC(mm)
	if highQC != nil {
		if err := r.verifyQC(highQC); err != nil {
			log.Error(ctx, "Failed to verify qc", err)
			return
		}
	}

	r.leaderPhase = r.leaderPhase.NextPhase()

	newValue := <-r.cluster.inputCh
	err := r.transport.Broadcast(ctx, Msg{
		Sender:  r.id,
		Type:    MsgPrepare,
		View:    r.view,
		Value:   newValue,
		Justify: highQC,
	})
	if err != nil {
		log.Error(ctx, "Failed to broadcast prepare", err)
	}
}

func (r *Replica) sendNewView(ctx context.Context) error {
	nextLeader := r.cluster.Leader(r.view)

	return r.transport.SendTo(ctx, nextLeader, Msg{
		Sender:  r.id,
		Type:    MsgNewView,
		View:    r.view - 1,
		Justify: r.prepareQC,
	})
}

func (r *Replica) nextView(ctx context.Context) error {
	r.view++
	r.phase = PreparePhase
	r.leaderPhase = PreparePhase
	r.prepareQC = nil
	r.lockedQC = nil

	return r.sendNewView(ctx)
}

func (r *Replica) replicaDuty(ctx context.Context, msg Msg, leader ID) {
	currentPhase := r.phase
	r.phase = r.phase.NextPhase()

	switch currentPhase {
	case PreparePhase:
		if !r.safeNode(msg.Justify) {
			log.Error(ctx, "Unsafe node", nil)
		} else {
			r.sendVote(ctx, MsgPrepare, msg.Value, leader)
		}
	case PreCommitPhase:
		r.prepareQC = msg.Justify
		r.sendVote(ctx, MsgPreCommit, msg.Value, leader)
	case CommitPhase:
		r.lockedQC = msg.Justify
		r.sendVote(ctx, MsgCommit, msg.Justify.Value, leader)
	case DecidePhase:
		log.Info(ctx, "Decided value", z.Str("value", msg.Justify.Value))
		r.cluster.outputCh <- msg.Justify.Value
	default:
		log.Debug(ctx, "Ignoring message in terminal phase")
	}
}

func (r *Replica) safeNode(qc *QC) bool {
	if qc == nil {
		// Initial view has no justification
		return true
	}

	if r.lockedQC == nil {
		return true
	}

	// Liveness rule
	return qc.View > r.lockedQC.View
}

func (r *Replica) sendVote(ctx context.Context, t MsgType, value string, leader ID) {
	voteMsg := Msg{
		Sender: r.id,
		Type:   t,
		View:   r.view,
		Value:  value,
		Vote:   true,
	}

	privKey := r.cluster.privateKeys[r.id-1]
	sig, err := Sign(privKey, t, r.view, value)
	if err != nil {
		log.Error(ctx, "Failed to sign vote", err)
		return
	}

	voteMsg.ParSig = sig

	if err := r.transport.SendTo(ctx, leader, voteMsg); err != nil {
		log.Error(ctx, "Failed to send vote", err)
	}
}

func (r *Replica) verifyQC(qc *QC) error {
	hash, err := Hash(qc.Type, qc.View, qc.Value)
	if err != nil {
		return err
	}

	pubKeys := make([]*k1.PublicKey, 0)
	for _, sig := range qc.Sigs {
		pk, err := k1util.Recover(hash[:], sig)
		if err != nil {
			return errors.Wrap(err, "bad signature")
		}
		pubKeys = append(pubKeys, pk)
	}

	if !r.cluster.HasQuorum(pubKeys) {
		return errors.New("quorum verification failed")
	}

	return nil
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

func createQC(msgs []*Msg) *QC {
	sigs := make([][]byte, len(msgs))

	for i, msg := range msgs {
		sigs[i] = msg.ParSig
	}

	return &QC{
		Type:  msgs[0].Type,
		View:  msgs[0].View,
		Value: msgs[0].Value,
		Sigs:  sigs,
	}
}
