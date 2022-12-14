// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package consensus

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/qbft"
	"github.com/obolnetwork/charon/p2p"
)

const (
	recvBuffer    = 100 // Allow buffering some initial messages when this node is late to start an instance.
	roundStart    = time.Millisecond * 750
	roundIncrease = time.Millisecond * 250
	protocolID    = "/charon/consensus/qbft/1.0.0"
)

// Protocols returns the supported protocols of this package in order of precedence.
func Protocols() []protocol.ID {
	return []protocol.ID{protocolID}
}

type subscriber func(ctx context.Context, duty core.Duty, value proto.Message) error

// newDefinition returns a qbft definition (this is constant across all consensus instances).
func newDefinition(nodes int, subs func() []subscriber) qbft.Definition[core.Duty, [32]byte] {
	quorum := qbft.Definition[int, int]{Nodes: nodes}.Quorum()

	return qbft.Definition[core.Duty, [32]byte]{
		// IsLeader is a deterministic leader election function.
		IsLeader: func(duty core.Duty, round, process int64) bool {
			return leader(duty, round, nodes) == process
		},

		// Decide sends consensus output to subscribers.
		Decide: func(ctx context.Context, duty core.Duty, _ [32]byte, qcommit []qbft.Msg[core.Duty, [32]byte]) {
			defer endCtxSpan(ctx) // End the parent tracing span when decided
			value, ok, err := msgValue(qcommit[0].(msg).msg)
			if err != nil {
				log.Error(ctx, "Get decided value", err)
				return
			} else if !ok {
				log.Error(ctx, "Missing decided value", nil)
				return
			}

			for _, sub := range subs() {
				if err := sub(ctx, duty, value); err != nil {
					log.Warn(ctx, "Subscriber error", err)
				}
			}
		},

		NewTimer: newRoundTimer, // newRoundTimer returns a 750ms+(round*250ms) period timer.

		// LogUponRule logs upon rules at debug level.
		LogUponRule: func(ctx context.Context, _ core.Duty, _, round int64,
			_ qbft.Msg[core.Duty, [32]byte], uponRule qbft.UponRule,
		) {
			log.Debug(ctx, "QBFT upon rule triggered", z.Any("rule", uponRule), z.I64("round", round))
		},

		// LogRoundChange logs round changes at debug level.
		LogRoundChange: func(ctx context.Context, duty core.Duty, process,
			round, newRound int64, uponRule qbft.UponRule, msgs []qbft.Msg[core.Duty, [32]byte],
		) {
			fields := []z.Field{
				z.Any("rule", uponRule),
				z.I64("round", round),
				z.I64("new_round", newRound),
			}

			steps := groupRoundMessages(msgs, nodes, round, int(leader(duty, round, nodes)))
			for _, step := range steps {
				fields = append(fields, z.Str(step.Type.String(), fmtStepPeers(step)))
			}
			if uponRule == qbft.UponRoundTimeout {
				fields = append(fields, z.Str("timeout_reason", timeoutReason(steps, round, quorum)))
			}

			log.Debug(ctx, "QBFT round changed", fields...)
		},

		LogUnjust: func(ctx context.Context, _ core.Duty, _ int64, msg qbft.Msg[core.Duty, [32]byte]) {
			log.Warn(ctx, "Unjustified consensus message from peer", nil,
				z.Any("type", msg.Type()),
				z.I64("peer", msg.Source()),
			)
		},

		// Nodes is the number of nodes.
		Nodes: nodes,

		// FIFOLimit caps the max buffered messages per peer.
		FIFOLimit: recvBuffer,
	}
}

// New returns a new consensus QBFT component.
func New(tcpNode host.Host, sender *p2p.Sender, peers []p2p.Peer, p2pKey *ecdsa.PrivateKey,
	deadliner core.Deadliner, snifferFunc func(*pbv1.SniffedConsensusInstance),
) (*Component, error) {
	// Extract peer pubkeys.
	keys := make(map[int64]*ecdsa.PublicKey)
	var labels []string
	for i, p := range peers {
		labels = append(labels, fmt.Sprintf("%d:%s", p.Index, p.Name))

		pk, err := p.PublicKey()
		if err != nil {
			return nil, err
		}

		keys[int64(i)] = pk
	}

	c := &Component{
		tcpNode:     tcpNode,
		sender:      sender,
		peers:       peers,
		peerLabels:  labels,
		privkey:     p2pKey,
		pubkeys:     keys,
		deadliner:   deadliner,
		recvBuffers: make(map[core.Duty]chan msg),
		snifferFunc: snifferFunc,
		dropFilter:  log.Filter(),
	}

	c.def = newDefinition(len(peers), c.subscribers)

	return c, nil
}

// Component implements core.Consensus.
type Component struct {
	// Immutable state
	tcpNode     host.Host
	sender      *p2p.Sender
	peerLabels  []string
	peers       []p2p.Peer
	pubkeys     map[int64]*ecdsa.PublicKey
	privkey     *ecdsa.PrivateKey
	def         qbft.Definition[core.Duty, [32]byte]
	subs        []subscriber
	deadliner   core.Deadliner
	snifferFunc func(*pbv1.SniffedConsensusInstance)
	dropFilter  z.Field // Filter buffer overflow errors (possible DDoS)

	// Mutable state
	recvMu      sync.Mutex
	recvBuffers map[core.Duty]chan msg // Instance outer receive buffers.
}

// Subscribe registers a callback for unsigned duty data proposals from leaders.
// Note this function is not thread safe, it should be called *before* Start and Propose.
func (c *Component) Subscribe(fn func(ctx context.Context, duty core.Duty, set core.UnsignedDataSet) error) {
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

// subscribers returns the subscribers.
func (c *Component) subscribers() []subscriber {
	return c.subs
}

// SubscribePriority registers a callback for priority protocol message proposals from leaders.
// Note this function is not thread safe, it should be called *before* Start and Propose.
func (c *Component) SubscribePriority(fn func(ctx context.Context, duty core.Duty, msg *pbv1.PriorityResult) error) {
	c.subs = append(c.subs, func(ctx context.Context, duty core.Duty, value proto.Message) error {
		msg, ok := value.(*pbv1.PriorityResult)
		if !ok {
			return nil
		}

		return fn(ctx, duty, msg)
	})
}

// Start registers the libp2p receive handler and starts a goroutine that cleans state. This should only be called once.
func (c *Component) Start(ctx context.Context) {
	p2p.RegisterHandler("qbft", c.tcpNode, protocolID,
		func() proto.Message { return new(pbv1.ConsensusMsg) },
		c.handle)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case duty := <-c.deadliner.C():
				c.deleteRecvChan(duty)
			}
		}
	}()
}

// Propose participants in a consensus instance proposing the provided unsigned data set.
// It returns on error or nil when the context is cancelled.
func (c *Component) Propose(ctx context.Context, duty core.Duty, data core.UnsignedDataSet) error {
	// Hash the proposed data, since qbft only supports simple comparable values.
	value, err := core.UnsignedDataSetToProto(data)
	if err != nil {
		return err
	}

	return c.propose(ctx, duty, value)
}

// ProposePriority participants in a consensus instance proposing the provided priority message.
// It returns on error or nil when the context is cancelled.
func (c *Component) ProposePriority(ctx context.Context, duty core.Duty, msg *pbv1.PriorityResult) error {
	return c.propose(ctx, duty, msg)
}

// propose participants in a consensus instance proposing the provided value.
// It returns on error or nil when the context is cancelled.
func (c *Component) propose(ctx context.Context, duty core.Duty, value proto.Message) error {
	ctx = log.WithTopic(ctx, "qbft")
	ctx = log.WithCtx(ctx, z.Any("duty", duty))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if !c.deadliner.Add(duty) {
		log.Warn(ctx, "Skipping consensus for expired duty", nil)
		return nil
	}

	log.Debug(ctx, "QBFT consensus instance starting", z.Any("peers", c.peerLabels))

	hash, err := hashProto(value)
	if err != nil {
		return err
	}

	peerIdx, err := c.getPeerIdx()
	if err != nil {
		return err
	}

	// Create a transport handles sending and receiving for this instance.
	t := transport{
		component:  c,
		values:     map[[32]byte]proto.Message{hash: value},
		recvBuffer: make(chan qbft.Msg[core.Duty, [32]byte]),
		sniffer:    newSniffer(int64(c.def.Nodes), peerIdx),
	}

	// Provide sniffed buffer to snifferFunc at the end.
	defer func() {
		c.snifferFunc(t.sniffer.Instance())
	}()

	// Start a receiving goroutine.
	go t.ProcessReceives(ctx, c.getRecvBuffer(duty))

	// Create a qbft transport from the transport
	qt := qbft.Transport[core.Duty, [32]byte]{
		Broadcast: t.Broadcast,
		Receive:   t.recvBuffer,
	}

	// Instrument consensus instance.
	var (
		t0      = time.Now()
		def     = c.def
		decided bool
	)
	// Wrap Decide function of c.def to instrument consensus instance with provided start time (t0) and decided round.
	def.Decide = func(ctx context.Context, duty core.Duty, val [32]byte, qcommit []qbft.Msg[core.Duty, [32]byte]) {
		decided = true
		instrumentConsensus(duty, qcommit[0].Round(), t0)
		c.def.Decide(ctx, duty, val, qcommit)
	}

	// Run the algo, blocking until the context is cancelled.
	err = qbft.Run[core.Duty, [32]byte](ctx, def, qt, duty, peerIdx, hash)
	if err != nil && !isContextErr(err) {
		consensusError.Inc()
		return err // Only return non-context errors.
	}

	if !decided {
		consensusTimeout.WithLabelValues(duty.Type.String()).Inc()
	}

	return nil
}

// handle processes an incoming consensus wire message.
func (c *Component) handle(ctx context.Context, _ peer.ID, req proto.Message) (proto.Message, bool, error) {
	t0 := time.Now()

	pbMsg, ok := req.(*pbv1.ConsensusMsg)
	if !ok {
		return nil, false, errors.New("invalid consensus message type")
	}

	if pbMsg.Msg == nil || pbMsg.Msg.Duty == nil {
		return nil, false, errors.New("invalid consensus message fields")
	}

	duty := core.DutyFromProto(pbMsg.Msg.Duty)
	if !duty.Type.Valid() {
		return nil, false, errors.New("invalid consensus message duty type", z.Str("type", duty.Type.String()))
	}
	ctx = log.WithCtx(ctx, z.Any("duty", duty))

	if ok, err := verifyMsgSig(pbMsg.Msg, c.pubkeys[pbMsg.Msg.PeerIdx]); err != nil {
		return nil, false, errors.Wrap(err, "verify consensus message signature", z.Any("duty", duty))
	} else if !ok {
		return nil, false, errors.New("invalid consensus message signature", z.Any("duty", duty))
	}

	for _, msg := range pbMsg.Justification {
		if ok, err := verifyMsgSig(msg, c.pubkeys[msg.PeerIdx]); err != nil {
			return nil, false, errors.Wrap(err, "verify consensus justification signature", z.Any("duty", duty))
		} else if !ok {
			return nil, false, errors.New("invalid consensus justification signature", z.Any("duty", duty))
		}
	}
	msg, err := newMsg(pbMsg.Msg, pbMsg.Justification)
	if err != nil {
		return nil, false, err
	}

	if !c.deadliner.Add(duty) {
		return nil, false, errors.New("duty expired", z.Any("duty", duty), c.dropFilter)
	}

	if ctx.Err() != nil {
		return nil, false, errors.Wrap(ctx.Err(), "receive cancelled during verification", z.Any("duty", duty),
			z.Any("duration", time.Since(t0)))
	}

	select {
	case c.getRecvBuffer(duty) <- msg:
		return nil, false, nil
	case <-ctx.Done():
		return nil, false, errors.Wrap(ctx.Err(), "timeout enqueuing receive buffer",
			z.Any("duty", duty), z.Any("duration", time.Since(t0)))
	}
}

// getRecvBuffer returns a receive buffer for the duty.
func (c *Component) getRecvBuffer(duty core.Duty) chan msg {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	ch, ok := c.recvBuffers[duty]
	if !ok {
		ch = make(chan msg, recvBuffer)
		c.recvBuffers[duty] = ch
	}

	return ch
}

// deleteRecvChan deletes the receive channel and recvDropped map entry for the duty.
func (c *Component) deleteRecvChan(duty core.Duty) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	delete(c.recvBuffers, duty)
}

// getPeerIdx returns the local peer index.
func (c *Component) getPeerIdx() (int64, error) {
	peerIdx := int64(-1)
	for i, p := range c.peers {
		if c.tcpNode.ID() == p.ID {
			peerIdx = int64(i)
		}
	}
	if peerIdx == -1 {
		return 0, errors.New("local libp2p host not in peer list")
	}

	return peerIdx, nil
}

func isContextErr(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

// endCtxSpan ends the parent span if included in the context.
func endCtxSpan(ctx context.Context) {
	trace.SpanFromContext(ctx).End()
}

// roundStep groups consensus round messages by type and peer status.
type roundStep struct {
	Type    qbft.MsgType
	Present []int
	Missing []int
	Peers   int
}

// groupRoundMessages groups messages by type and returns which peers were present and missing for each type.
func groupRoundMessages(msgs []qbft.Msg[core.Duty, [32]byte], peers int, round int64, leader int) []roundStep {
	// checkPeers returns two slices of peer indexes, one with peers
	// present with the message type and one with messing peers.
	checkPeers := func(typ qbft.MsgType) (present []int, missing []int) {
		for i := 0; i < peers; i++ {
			var included bool
			for _, msg := range msgs {
				if msg.Type() == typ && msg.Source() == int64(i) {
					included = true
					break
				}
			}
			if included {
				present = append(present, i)
				continue
			}

			if typ == qbft.MsgPrePrepare && i != leader {
				// Only leader can be missing for pre-prepare.
				continue
			}

			if typ == qbft.MsgRoundChange && round == 1 {
				// Round changes only applicable to rounds > 1.
				continue
			}

			missing = append(missing, i)
		}

		return present, missing
	}

	var resp []roundStep
	for _, typ := range []qbft.MsgType{qbft.MsgPrePrepare, qbft.MsgPrepare, qbft.MsgCommit, qbft.MsgRoundChange} {
		present, missing := checkPeers(typ)
		resp = append(resp, roundStep{
			Type:    typ,
			Present: present,
			Missing: missing,
			Peers:   peers,
		})
	}

	return resp
}

func timeoutReason(steps []roundStep, round int64, quorum int) string {
	byType := make(map[qbft.MsgType]roundStep)
	for _, step := range steps {
		byType[step.Type] = step
	}

	if round > 1 { // Quorum round changes are required for leader to propose for rounds > 1.
		if step := byType[qbft.MsgRoundChange]; len(step.Present) < quorum {
			return "insufficient round-changes, missing peers=" + fmt.Sprint(step.Missing)
		}
	}

	if step := byType[qbft.MsgPrePrepare]; len(step.Present) == 0 {
		return "no pre-prepare, missing leader=" + fmt.Sprint(step.Missing)
	}

	if step := byType[qbft.MsgPrepare]; len(step.Present) < quorum {
		return "insufficient prepares, missing peers=" + fmt.Sprint(step.Missing)
	}

	if step := byType[qbft.MsgCommit]; len(step.Present) < quorum {
		return "insufficient commits, missing peers=" + fmt.Sprint(step.Missing)
	}

	return "unknown reason"
}

// fmtStepPeers returns a string representing the present and missing peers.
func fmtStepPeers(step roundStep) string {
	var resp []string
	for i := 0; i < step.Peers; i++ {
		resp = append(resp, "_")
	}

	for _, i := range step.Present {
		resp[i] = "*"
	}

	for _, i := range step.Missing {
		resp[i] = "?"
	}

	return strings.Join(resp, "")
}

// leader return the deterministic leader index.
func leader(duty core.Duty, round int64, nodes int) int64 {
	return ((duty.Slot) + int64(duty.Type) + round) % int64(nodes)
}

// newRoundTimer returns a 750ms+(round*250ms) period timer.
//
// TODO(corver): Round timeout is a tradeoff between fast rounds to skip unavailable nodes
// and slow rounds to allow consensus in high latency clusters. Dynamic timeout based on
// recent network conditions could be an option.
func newRoundTimer(round int64) (<-chan time.Time, func()) {
	timer := time.NewTimer(roundStart + (time.Duration(round) * roundIncrease))
	return timer.C, func() { timer.Stop() }
}
