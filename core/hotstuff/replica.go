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
	"github.com/obolnetwork/charon/core"
)

// Replica represents a single HotStuff replica.
// A replica can also serve as the leader depending on the view.
type Replica struct {
	// Immutable state
	id           ID
	duty         core.Duty
	cluster      Cluster
	transport    Transport
	privateKey   *k1.PrivateKey
	decidedFunc  DecidedFunc
	valueCh      <-chan Value
	receiveCh    <-chan *Msg
	phaseTimeout time.Duration

	// Mutable state
	view        View
	phase       Phase
	leaderPhase Phase
	valuesMap   map[Hash]Value
	prepareQC   *QC
	lockedQC    *QC
	collector   *Collector
}

func NewReplica(id ID, duty core.Duty,
	cluster Cluster, transport Transport, receiveCh <-chan *Msg,
	privateKey *k1.PrivateKey, decidedFunc DecidedFunc,
	valueCh <-chan Value, phaseTimeout time.Duration,
) *Replica {
	return &Replica{
		id:           id,
		duty:         duty,
		cluster:      cluster,
		transport:    transport,
		privateKey:   privateKey,
		decidedFunc:  decidedFunc,
		valueCh:      valueCh,
		receiveCh:    receiveCh,
		phaseTimeout: phaseTimeout,
		view:         1,
		phase:        PreparePhase,
		leaderPhase:  PreparePhase,
		valuesMap:    make(map[Hash]Value),
		collector:    NewCollector(),
	}
}

func (r *Replica) Run(ctx context.Context) error {
	ctx = log.WithCtx(log.WithTopic(ctx, "hotstuff"), z.Uint("replica", uint(r.id)))

	// Initially all replicas send a NewView message to the leader.
	if err := r.sendNewView(ctx); err != nil {
		log.Error(ctx, "Failed to send new_view", err)

		return err
	}

	for {
		select {
		case msg, ok := <-r.receiveCh:
			if !ok {
				return errors.New("receive channel closed")
			}
			r.handleMsg(ctx, msg)
		case <-ctx.Done():
			return nil
		case <-time.After(r.phaseTimeout):
			log.Warn(ctx, "Phase timeout", nil)

			return errors.New("phase timeout")
			// if err := r.nextView(ctx); err != nil {
			// 	log.Error(ctx, "Failed to move to next view", err)

			// 	return err
			// }
		}
	}
}

func (r *Replica) handleMsg(ctx context.Context, msg *Msg) {
	if msg.Duty != r.duty {
		return
	}

	ctx = log.WithCtx(ctx, z.U64("view", uint64(r.view)), z.Str("phase", r.phase.String()))

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
		if err := r.replicaDuty(ctx, msg, leader); err != nil {
			log.Error(ctx, "Failed to handle msg as replica", err)
		}
	}
}

func (r *Replica) leaderDuty(ctx context.Context, msg *Msg) {
	validLeaderMsgInPhase := map[Phase]MsgType{
		PreparePhase:   MsgPrepare,
		PreCommitPhase: MsgPrepare,
		CommitPhase:    MsgPreCommit,
		DecidePhase:    MsgCommit,
	}

	if t, ok := validLeaderMsgInPhase[r.leaderPhase]; !ok || msg.Type != t {
		return
	}

	sender, err := r.getSenderID(msg)
	if err != nil {
		log.Error(ctx, "Failed to get sender id", err)
	}

	r.collector.AddMsg(msg, sender)
	mm := r.collector.MatchingMsg(MsgPrepare, r.view)
	if len(mm) < int(r.cluster.Threshold()) {
		return
	}

	qc, err := createQC(mm)
	if err != nil {
		log.Error(ctx, "Failed to create qc", err)
		return
	}
	if err := r.verifyQC(qc); err != nil {
		log.Error(ctx, "Failed to verify qc", err)
		return
	}

	r.leaderPhase = r.leaderPhase.NextPhase()

	t := msg.Type.NextMsgType()
	err = r.transport.Broadcast(ctx, &Msg{
		Duty: r.duty,
		Type: t,
		View: r.view,
		QC:   qc,
	})
	if err != nil {
		log.Error(ctx, "Leader failed to broadcast", err)
	}
}

func (r *Replica) leaderNewView(ctx context.Context, msg *Msg) {
	if r.leaderPhase != PreparePhase || msg.Type != MsgNewView {
		return
	}

	sender, err := r.getSenderID(msg)
	if err != nil {
		log.Error(ctx, "Failed to get sender id", err)
	}

	r.collector.AddMsg(msg, sender)
	mm := r.collector.MatchingMsg(MsgNewView, r.view-1)
	if len(mm) < int(r.cluster.Threshold()) {
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

	value := <-r.valueCh
	err = r.transport.Broadcast(ctx, &Msg{
		Duty:  r.duty,
		Type:  MsgPrepare,
		View:  r.view,
		Value: value,
		QC:    highQC,
	})
	if err != nil {
		log.Error(ctx, "Failed to broadcast prepare", err)
	}
}

func (r *Replica) nextView(ctx context.Context) error {
	r.view++
	r.phase = PreparePhase
	r.leaderPhase = PreparePhase
	r.valuesMap = make(map[Hash]Value)

	return r.sendNewView(ctx)
}

func (r *Replica) replicaDuty(ctx context.Context, msg *Msg, leader ID) (err error) {
	currentPhase := r.phase
	r.phase = r.phase.NextPhase()

	switch currentPhase {
	case PreparePhase:
		if !r.safeNode(msg.QC) {
			log.Error(ctx, "Unsafe node", nil)
		} else {
			valueHash, herr := HashValue(msg.Value)
			if herr != nil {
				err = herr
			} else {
				r.valuesMap[valueHash] = msg.Value
				err = r.sendVote(ctx, MsgPrepare, valueHash, leader)
			}
		}
	case PreCommitPhase:
		r.prepareQC = msg.QC
		err = r.sendVote(ctx, MsgPreCommit, msg.QC.ValueHash, leader)
	case CommitPhase:
		r.lockedQC = msg.QC
		err = r.sendVote(ctx, MsgCommit, msg.QC.ValueHash, leader)
	case DecidePhase:
		value := r.valuesMap[msg.QC.ValueHash]
		r.decidedFunc(value, r.view)
	default:
		log.Debug(ctx, "Ignoring message in terminal phase")
	}

	return err
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

func (r *Replica) sendVote(ctx context.Context, t MsgType, valueHash [32]byte, leader ID) error {
	msg := Msg{
		Duty:      r.duty,
		Type:      t,
		View:      r.view,
		ValueHash: valueHash,
		Vote:      true,
	}

	return r.sendMsg(ctx, &msg, leader)
}

func (r *Replica) sendNewView(ctx context.Context) error {
	nextLeader := r.cluster.Leader(r.view)

	msg := Msg{
		Duty: r.duty,
		Type: MsgNewView,
		View: r.view - 1,
		QC:   r.prepareQC,
	}

	return r.sendMsg(ctx, &msg, nextLeader)
}

func (r *Replica) sendMsg(ctx context.Context, msg *Msg, leader ID) error {
	sig, err := Sign(r.privateKey, msg.Type, msg.View, msg.ValueHash)
	if err != nil {
		return errors.Wrap(err, "sign msg")
	}

	msgWithSig := *msg
	msgWithSig.Signature = sig

	if err := r.transport.SendTo(ctx, leader, &msgWithSig); err != nil {
		return errors.Wrap(err, "send msg")
	}

	return nil
}

func (r *Replica) getSenderID(msg *Msg) (ID, error) {
	hash, err := HashMsg(msg.Type, msg.View, msg.ValueHash)
	if err != nil {
		return InvalidID, errors.Wrap(err, "hash msg")
	}

	pk, err := k1util.Recover(hash[:], msg.Signature)
	if err != nil {
		return InvalidID, errors.Wrap(err, "bad msg signature")
	}

	id := r.cluster.PublicKeyToID(pk)
	if id == InvalidID {
		return InvalidID, errors.New("unknown sender")
	}

	return id, nil
}

func (r *Replica) verifyQC(qc *QC) error {
	pubKeys := make([]*k1.PublicKey, 0)
	for _, sig := range qc.Signatures {
		hash, err := HashMsg(qc.Type, qc.View, qc.ValueHash)
		if err != nil {
			return errors.Wrap(err, "hash qc")
		}
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
	highQC := msgs[0].QC

	for _, msg := range msgs[1:] {
		if msg.QC != nil && (highQC == nil || msg.QC.View > highQC.View) {
			highQC = msg.QC
		}
	}

	return highQC
}

func createQC(msgs []*Msg) (*QC, error) {
	sigs := make([][]byte, len(msgs))

	for i, msg := range msgs {
		sigs[i] = msg.Signature

		if i > 0 {
			if msg.Type != msgs[0].Type || msg.View != msgs[0].View || msg.ValueHash != msgs[0].ValueHash {
				return nil, errors.New("msg mismatch")
			}
		}
	}

	return &QC{
		Type:       msgs[0].Type,
		View:       msgs[0].View,
		ValueHash:  msgs[0].ValueHash,
		Signatures: sigs,
	}, nil
}
