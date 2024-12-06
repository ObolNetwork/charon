// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import (
	"context"
	"slices"
	"sync"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus/metrics"
	"github.com/obolnetwork/charon/core/consensus/protocols"
	"github.com/obolnetwork/charon/core/consensus/utils"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	hs "github.com/obolnetwork/charon/core/hotstuff"
	"github.com/obolnetwork/charon/p2p"
)

type subscriber func(ctx context.Context, duty core.Duty, value proto.Message) error

// Consensus implements core.Consensus.
type Consensus struct {
	// Immutable state
	id           hs.ID
	tcpNode      host.Host
	sender       *p2p.Sender
	peers        []p2p.Peer
	subs         []subscriber
	deadliner    core.Deadliner
	metrics      metrics.ConsensusMetrics
	cluster      *cluster
	peersTracker core.PeersTracker

	// Mutable state
	mutable struct {
		sync.Mutex
		instances map[core.Duty]*utils.InstanceIO[hs.Value, *hs.Msg]
	}
}

var _ core.Consensus = (*Consensus)(nil)

// NewConsensus returns a new consensus HotStuff component.
func NewConsensus(tcpNode host.Host, sender *p2p.Sender, peers []p2p.Peer,
	p2pKey *k1.PrivateKey, deadliner core.Deadliner, peersTracker core.PeersTracker,
) (*Consensus, error) {
	var id hs.ID

	keys := make([]*k1.PublicKey, len(peers))
	for i, p := range peers {
		if p.ID == tcpNode.ID() {
			id = hs.ID(i)
		}
		pk, err := p.PublicKey()
		if err != nil {
			return nil, errors.Wrap(err, "get public key")
		}
		keys[i] = pk
	}

	cluster := newCluster(uint(len(peers)), p2pKey, keys)

	c := &Consensus{
		id:           id,
		tcpNode:      tcpNode,
		sender:       sender,
		peers:        peers,
		deadliner:    deadliner,
		metrics:      metrics.NewConsensusMetrics(protocols.HotStuffv1ProtocolID),
		cluster:      cluster,
		peersTracker: peersTracker,
	}

	c.mutable.instances = make(map[core.Duty]*utils.InstanceIO[hs.Value, *hs.Msg])

	return c, nil
}

func (*Consensus) ProtocolID() protocol.ID {
	return protocols.HotStuffv1ProtocolID
}

func (c *Consensus) Start(ctx context.Context) {
	const logTopic = "hotstuff"

	p2p.RegisterHandler(logTopic, c.tcpNode,
		protocols.HotStuffv1ProtocolID,
		func() proto.Message { return new(pbv1.HotStuffMsg) },
		c.handle)

	go func() {
		for {
			select {
			case <-ctx.Done():
				p2p.RegisterHandler(logTopic, c.tcpNode, protocols.HotStuffv1ProtocolID,
					func() proto.Message { return new(pbv1.HotStuffMsg) }, nil)

				return
			case duty := <-c.deadliner.C():
				c.mutable.Lock()
				delete(c.mutable.instances, duty)
				c.mutable.Unlock()
			}
		}
	}()
}

func (c *Consensus) Participate(ctx context.Context, duty core.Duty) error {
	if duty.Type == core.DutyAggregator || duty.Type == core.DutySyncContribution {
		return nil // No consensus participate for potential no-op aggregation duties.
	}

	if !featureset.Enabled(featureset.ConsensusParticipate) {
		return nil // Wait for Propose to start.
	}

	inst := c.getInstanceIO(duty)

	if err := inst.MarkParticipated(); err != nil {
		return errors.Wrap(err, "participate consensus", z.Any("duty", duty))
	}

	if !inst.MaybeStart() {
		return nil // Instance already running.
	}

	return c.runInstance(ctx, duty)
}

func (c *Consensus) Propose(ctx context.Context, duty core.Duty, data core.UnsignedDataSet) error {
	value, err := core.UnsignedDataSetToProto(data)
	if err != nil {
		return err
	}

	return c.propose(ctx, duty, value)
}

func (c *Consensus) Subscribe(fn func(context.Context, core.Duty, core.UnsignedDataSet) error) {
	c.subs = append(c.subs, func(ctx context.Context, duty core.Duty, value proto.Message) error {
		unsignedPB, ok := value.(*pbv1.UnsignedDataSet)
		if !ok {
			return nil
		}

		unsigned, err := core.UnsignedDataSetFromProto(duty.Type, unsignedPB)
		if err != nil {
			return err
		}

		return fn(ctx, duty, unsigned)
	})
}

// Broadcast implements hotstuff.Transport.
func (c *Consensus) Broadcast(ctx context.Context, msg *hs.Msg) (err error) {
	for i := range c.peers {
		if err = c.SendTo(ctx, hs.ID(i), msg); err != nil {
			break
		}
	}

	return err
}

// SendTo implements hotstuff.Transport.
func (c *Consensus) SendTo(ctx context.Context, id hs.ID, msg *hs.Msg) (err error) {
	if int(id) >= len(c.peers) {
		return errors.New("invalid peer ID")
	}

	peer := c.peers[id]
	if c.tcpNode.ID() == peer.ID {
		recvBufferCh := c.getRecvBuffer(msg.Duty)
		if recvBufferCh != nil {
			select {
			case recvBufferCh <- msg:
			case <-ctx.Done():
				err = ctx.Err()
			}
		}
	} else {
		protoMsg := msg.ToProto()
		if err2 := c.sender.SendAsync(ctx, c.tcpNode, protocols.HotStuffv1ProtocolID, peer.ID, protoMsg); err2 != nil {
			err = errors.Wrap(err2, "failed to send message")
		}
	}

	return err
}

func (c *Consensus) getInstanceIO(duty core.Duty) *utils.InstanceIO[hs.Value, *hs.Msg] {
	c.mutable.Lock()
	defer c.mutable.Unlock()

	inst, ok := c.mutable.instances[duty]
	if !ok {
		inst = utils.NewInstanceIO[hs.Value, *hs.Msg]()
		c.mutable.instances[duty] = inst
	}

	return inst
}

func (c *Consensus) getRecvBuffer(duty core.Duty) chan *hs.Msg {
	return c.getInstanceIO(duty).RecvBuffer
}

func (c *Consensus) propose(ctx context.Context, duty core.Duty, value proto.Message) error {
	inst := c.getInstanceIO(duty)

	if err := inst.MarkProposed(); err != nil {
		return errors.Wrap(err, "propose consensus", z.Any("duty", duty))
	}

	protoBytes, err := proto.Marshal(value)
	if err != nil {
		return errors.Wrap(err, "marshal input value")
	}

	select {
	case <-ctx.Done():
		return errors.Wrap(ctx.Err(), "context done")
	case inst.ValueCh <- protoBytes:
	}

	// Instrument consensus duration using decidedAt output.
	proposedAt := time.Now()
	defer func() {
		select {
		case decidedAt := <-inst.DecidedAtCh:
			duration := decidedAt.Sub(proposedAt)
			c.metrics.ObserveConsensusDuration(duty.Type.String(), "none", duration.Seconds())
		default:
		}
	}()

	if !inst.MaybeStart() { // Participate was already called, instance is running.
		return <-inst.ErrCh
	}

	return c.runInstance(ctx, duty)
}

func (c *Consensus) runInstance(ctx context.Context, duty core.Duty) (err error) {
	inst := c.getInstanceIO(duty)
	defer func() {
		inst.ErrCh <- err // Send resulting error to errCh.
	}()

	if !c.deadliner.Add(duty) {
		log.Warn(ctx, "Skipping consensus for expired duty", nil)
		return nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var decided bool

	decidedFn := func(value hs.Value, view hs.View) {
		decided = true
		inst.DecidedAtCh <- time.Now()

		leaderID := c.cluster.Leader(view)
		leaderName := c.peers[leaderID].Name
		log.Debug(ctx, "HotStuff consensus decided",
			z.Str("duty", duty.Type.String()),
			z.U64("slot", duty.Slot),
			z.U64("view", uint64(view)),
			z.U64("leader_id", uint64(leaderID)),
			z.Str("leader_name", leaderName))

		c.metrics.SetDecidedLeaderIndex(duty.Type.String(), int64(leaderID))
		c.metrics.SetDecidedRounds(duty.Type.String(), "none", int64(view))

		uds := &pbv1.UnsignedDataSet{}
		if err := proto.Unmarshal(value, uds); err != nil {
			log.Warn(ctx, "Failed to unmarshal value", err)
		}

		for _, sub := range c.subs {
			if err := sub(ctx, duty, uds); err != nil {
				log.Warn(ctx, "Subscriber error", err)
			}
		}
	}

	uids := c.unreachableIDs()
	for _, uid := range uids {
		log.Warn(ctx, "Detected unreachable peer", nil, z.U64("id", uint64(uid)))
	}

	r := hs.NewReplica(c.id, duty, c.cluster, uids, c, inst.RecvBuffer, c.cluster.privateKey, decidedFn, inst.ValueCh)
	err = r.Run(ctx)
	if err != nil && !isContextErr(err) {
		c.metrics.IncConsensusError()
		return err // Only return non-context errors.
	}

	if !decided {
		c.metrics.IncConsensusTimeout(duty.Type.String(), "none")
		err = errors.New("consensus timeout", z.Str("duty", duty.String()))
	}

	return err
}

func (c *Consensus) handle(ctx context.Context, _ peer.ID, req proto.Message) (proto.Message, bool, error) {
	pbMsg, ok := req.(*pbv1.HotStuffMsg)
	if !ok || pbMsg == nil {
		return nil, false, errors.New("invalid consensus message")
	}

	duty := core.DutyFromProto(pbMsg.GetDuty())
	ctx = log.WithCtx(ctx, z.Any("duty", duty))

	if !c.deadliner.Add(duty) {
		return nil, false, errors.New("duty expired", z.Any("duty", duty))
	}

	msg := hs.ProtoToMsg(pbMsg)

	select {
	case c.getRecvBuffer(duty) <- msg:
		return nil, false, nil
	case <-ctx.Done():
		return nil, false, errors.Wrap(ctx.Err(), "timeout enqueuing receive buffer", z.Any("duty", duty))
	}
}

func (c *Consensus) unreachableIDs() (uids []hs.ID) {
	unreachable := c.peersTracker.Unreachable()

	for i, peer := range c.peers {
		if slices.Contains(unreachable, peer.ID) {
			uids = append(uids, hs.ID(i))
		}
	}

	return uids
}

func isContextErr(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}
