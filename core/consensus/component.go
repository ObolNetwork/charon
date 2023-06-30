// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/qbft"
	"github.com/obolnetwork/charon/p2p"
)

const (
	recvBuffer  = 100 // Allow buffering some initial messages when this node is late to start an instance.
	protocolID1 = "/charon/consensus/qbft/1.0.0"
	protocolID2 = "/charon/consensus/qbft/2.0.0"
)

// Protocols returns the supported protocols of this package in order of precedence.
func Protocols() []protocol.ID {
	return []protocol.ID{protocolID2, protocolID1}
}

type subscriber func(ctx context.Context, duty core.Duty, value proto.Message) error

// newDefinition returns a qbft definition (this is constant across all consensus instances).
func newDefinition(nodes int, subs func() []subscriber, roundTimer roundTimer,
	decideCallback func(qcommit []qbft.Msg[core.Duty, [32]byte]),
) qbft.Definition[core.Duty, [32]byte] {
	quorum := qbft.Definition[int, int]{Nodes: nodes}.Quorum()

	return qbft.Definition[core.Duty, [32]byte]{
		// IsLeader is a deterministic leader election function.
		IsLeader: func(duty core.Duty, round, process int64) bool {
			return leader(duty, round, nodes) == process
		},

		// Decide sends consensus output to subscribers.
		Decide: func(ctx context.Context, duty core.Duty, _ [32]byte, qcommit []qbft.Msg[core.Duty, [32]byte]) {
			defer endCtxSpan(ctx) // End the parent tracing span when decided
			msg, ok := qcommit[0].(msg)
			if !ok {
				log.Error(ctx, "Invalid message type", nil)
				return
			}

			anyValue, ok := msg.values[msg.valueHash]
			if !ok {
				log.Error(ctx, "Invalid value hash", nil)
				return
			}

			value, err := anyValue.UnmarshalNew()
			if err != nil {
				log.Error(ctx, "Invalid any value", err)
				return
			}

			decideCallback(qcommit)

			for _, sub := range subs() {
				if err := sub(ctx, duty, value); err != nil {
					log.Warn(ctx, "Subscriber error", err)
				}
			}
		},

		NewTimer: roundTimer.Timer,

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
func New(tcpNode host.Host, sender *p2p.Sender, peers []p2p.Peer, p2pKey *k1.PrivateKey,
	deadliner core.Deadliner, snifferFunc func(*pbv1.SniffedConsensusInstance),
) (*Component, error) {
	// Extract peer pubkeys.
	keys := make(map[int64]*k1.PublicKey)
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
		snifferFunc: snifferFunc,
		dropFilter:  log.Filter(),
		timerFunc:   getTimerFunc(),
	}
	c.mutable.recvBuffers = make(map[core.Duty]chan msg)
	c.mutable.inputValues = make(map[core.Duty]chan proto.Message)
	c.mutable.inputHashes = make(map[core.Duty]chan [32]byte)
	c.mutable.returnErrs = make(map[core.Duty]chan error)

	return c, nil
}

// Component implements core.Consensus.
type Component struct {
	// Immutable state
	tcpNode     host.Host
	sender      *p2p.Sender
	peerLabels  []string
	peers       []p2p.Peer
	pubkeys     map[int64]*k1.PublicKey
	privkey     *k1.PrivateKey
	subs        []subscriber
	deadliner   core.Deadliner
	snifferFunc func(*pbv1.SniffedConsensusInstance)
	dropFilter  z.Field // Filter buffer overflow errors (possible DDoS)
	timerFunc   timerFunc

	// Mutable state
	mutable struct {
		sync.Mutex
		recvBuffers map[core.Duty]chan msg           // Instance outer receive buffers.
		inputHashes map[core.Duty]chan [32]byte      // Instance input hash channels.
		inputValues map[core.Duty]chan proto.Message // Instance input value channels.
		returnErrs  map[core.Duty]chan error         // Instance return error channels.
	}
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
	p2p.RegisterHandler("qbft", c.tcpNode, protocolID1,
		func() proto.Message { return new(pbv1.ConsensusMsg) },
		c.handle, p2p.WithDelimitedProtocol(protocolID2))

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case duty := <-c.deadliner.C():
				c.deleteMutable(duty)
			}
		}
	}()
}

// Propose enqueues the proposed value to a consensus instance input channels.
// It either runs the consensus instance if it is not already running or
// waits until it completes, in both cases it returns the resulting error.
func (c *Component) Propose(ctx context.Context, duty core.Duty, data core.UnsignedDataSet) error {
	// Hash the proposed data, since qbft only supports simple comparable values.
	value, err := core.UnsignedDataSetToProto(data)
	if err != nil {
		return err
	}

	return c.propose(ctx, duty, value)
}

// ProposePriority enqueues the proposed value to a consensus instance input channels.
// It either runs the consensus instance if it is not already running or
// waits until it completes, in both cases it returns the resulting error.
func (c *Component) ProposePriority(ctx context.Context, duty core.Duty, msg *pbv1.PriorityResult) error {
	return c.propose(ctx, duty, msg)
}

// propose enqueues the proposed value to a consensus instance input channels.
// It either runs the consensus instance if it is not already running or
// waits until it completes, in both cases it returns the resulting error.
func (c *Component) propose(ctx context.Context, duty core.Duty, value proto.Message) error {
	hash, err := hashProto(value)
	if err != nil {
		return err
	}

	valCh, hashCh, errCh, running := c.getInstanceChans(duty)

	select {
	case valCh <- value:
	default:
		return errors.New("input channel full")
	}

	select {
	case hashCh <- hash:
	default:
		return errors.New("input channel full")
	}

	if running { // Participate was already called, instance is running.
		return <-errCh
	}

	return c.runInstance(ctx, duty)
}

// Participate runs a new a consensus instance if an eager timer is defined and Propose not already called.
// Note Propose must still be called for this peer to propose a value when leading a round.
func (c *Component) Participate(ctx context.Context, duty core.Duty) error {
	if duty.Type == core.DutyAggregator || duty.Type == core.DutySyncContribution {
		return nil // No eager consensus for potential no-op aggregation duties.
	}

	if !c.timerFunc(duty).Type().Eager() {
		return nil // Not an eager start timer, wait for Propose to start.
	}

	if _, _, _, running := c.getInstanceChans(duty); running {
		return nil // Instance already running.
	}

	return c.runInstance(ctx, duty)
}

// runInstance blocks and runs a consensus instance for the given duty.
// It returns an error or nil when the context is cancelled.
func (c *Component) runInstance(ctx context.Context, duty core.Duty) (err error) {
	roundTimer := c.timerFunc(duty)
	ctx = log.WithTopic(ctx, "qbft")
	ctx = log.WithCtx(ctx, z.Any("duty", duty))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if !c.deadliner.Add(duty) {
		log.Warn(ctx, "Skipping consensus for expired duty", nil)
		return nil
	}

	log.Debug(ctx, "QBFT consensus instance starting",
		z.Any("peers", c.peerLabels),
		z.Any("timer", string(roundTimer.Type())),
	)

	peerIdx, err := c.getPeerIdx()
	if err != nil {
		return err
	}

	// Instrument consensus instance.
	var (
		t0      = time.Now()
		decided bool
	)
	decideCallback := func(qcommit []qbft.Msg[core.Duty, [32]byte]) {
		decided = true
		instrumentConsensus(duty, qcommit[0].Round(), t0, roundTimer.Type())
	}

	valueCh, hashCh, errCh, _ := c.getInstanceChans(duty)
	defer func() {
		errCh <- err // Send resulting error to errCh.
	}()

	// Create a new qbft definition for this instance.
	def := newDefinition(len(c.peers), c.subscribers, roundTimer, decideCallback)

	// Create a new transport that handles sending and receiving for this instance.
	t := transport{
		component:  c,
		values:     make(map[[32]byte]*anypb.Any),
		valueCh:    valueCh,
		recvBuffer: make(chan qbft.Msg[core.Duty, [32]byte]),
		sniffer:    newSniffer(int64(def.Nodes), peerIdx),
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

	// Run the algo, blocking until the context is cancelled.
	err = qbft.Run[core.Duty, [32]byte](ctx, def, qt, duty, peerIdx, hashCh)
	if err != nil && !isContextErr(err) {
		consensusError.Inc()
		return err // Only return non-context errors.
	}

	if !decided {
		consensusTimeout.WithLabelValues(duty.Type.String(), string(roundTimer.Type())).Inc()

		return errors.New("consensus timeout", z.Str("duty", duty.String()))
	}

	return nil
}

// handle processes an incoming consensus wire message.
func (c *Component) handle(ctx context.Context, _ peer.ID, req proto.Message) (proto.Message, bool, error) {
	t0 := time.Now()

	pbMsg, ok := req.(*pbv1.ConsensusMsg)
	if !ok || pbMsg == nil {
		return nil, false, errors.New("invalid consensus message")
	}

	if err := verifyMsg(pbMsg.Msg, c.pubkeys); err != nil {
		return nil, false, err
	}

	duty := core.DutyFromProto(pbMsg.Msg.Duty)
	ctx = log.WithCtx(ctx, z.Any("duty", duty))

	for _, justification := range pbMsg.Justification {
		if err := verifyMsg(justification, c.pubkeys); err != nil {
			return nil, false, errors.Wrap(err, "invalid justification")
		}

		justDuty := core.DutyFromProto(justification.Duty)
		if justDuty != duty {
			return nil, false, errors.New(
				"qbft justification duty differs from message duty",
				z.Str("expected", duty.String()),
				z.Str("found", justDuty.String()),
			)
		}
	}

	values, err := valuesByHash(pbMsg.Values)
	if err != nil {
		return nil, false, err
	}

	msg, err := newMsg(pbMsg.Msg, pbMsg.Justification, values)
	if err != nil {
		return nil, false, err
	}

	if ctx.Err() != nil {
		return nil, false, errors.Wrap(ctx.Err(), "receive cancelled during verification",
			z.Any("duty", duty),
			z.Any("after", time.Since(t0)),
		)
	}

	if !c.deadliner.Add(duty) {
		return nil, false, errors.New("duty expired", z.Any("duty", duty), c.dropFilter)
	}

	select {
	case c.getRecvBuffer(duty) <- msg:
		return nil, false, nil
	case <-ctx.Done():
		return nil, false, errors.Wrap(ctx.Err(), "timeout enqueuing receive buffer",
			z.Any("duty", duty), z.Any("after", time.Since(t0)))
	}
}

// getRecvBuffer returns a receive buffer for the duty.
func (c *Component) getRecvBuffer(duty core.Duty) chan msg {
	c.mutable.Lock()
	defer c.mutable.Unlock()

	ch, ok := c.mutable.recvBuffers[duty]
	if !ok {
		ch = make(chan msg, recvBuffer)
		c.mutable.recvBuffers[duty] = ch
	}

	return ch
}

// getInstanceChans returns the duty's input value and hash and error channels and true if they were previously created.
func (c *Component) getInstanceChans(duty core.Duty) (chan proto.Message, chan [32]byte, chan error, bool) {
	c.mutable.Lock()
	defer c.mutable.Unlock()

	valCh, ok := c.mutable.inputValues[duty]
	if !ok { // Create new channels.
		valCh = make(chan proto.Message, 1)
		c.mutable.inputValues[duty] = valCh

		hashCh := make(chan [32]byte, 1)
		c.mutable.inputHashes[duty] = hashCh

		errCh := make(chan error, 1)
		c.mutable.returnErrs[duty] = errCh

		return valCh, hashCh, errCh, false
	}

	// Return existing channels.
	hashCh, ok := c.mutable.inputHashes[duty]
	if !ok {
		panic("bug: this should never happen")
	}

	errCh, ok := c.mutable.returnErrs[duty]
	if !ok {
		panic("bug: this should never happen")
	}

	return valCh, hashCh, errCh, true
}

// deleteMutable deletes the receive channel and recvDropped map entry for the duty.
func (c *Component) deleteMutable(duty core.Duty) {
	c.mutable.Lock()
	defer c.mutable.Unlock()

	delete(c.mutable.recvBuffers, duty)
	delete(c.mutable.inputHashes, duty)
	delete(c.mutable.inputValues, duty)
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

func verifyMsg(msg *pbv1.QBFTMsg, pubkeys map[int64]*k1.PublicKey) error {
	if msg == nil || msg.Duty == nil {
		return errors.New("invalid consensus message")
	}

	if typ := qbft.MsgType(msg.Type); !typ.Valid() {
		return errors.New("invalid consensus message type", z.Int("type", int(typ)))
	}

	if typ := core.DutyType(msg.Duty.Type); !typ.Valid() {
		return errors.New("invalid consensus message duty type", z.Int("type", int(typ)))
	}

	if msg.Round <= 0 {
		return errors.New("invalid consensus message round", z.I64("round", msg.Round))
	}
	if msg.PreparedRound < 0 {
		return errors.New("invalid consensus message prepared round")
	}

	msgPubkey, exists := pubkeys[msg.PeerIdx]
	if !exists {
		return errors.New("invalid peer index", z.I64("index", msg.PeerIdx))
	}

	if ok, err := verifyMsgSig(msg, msgPubkey); err != nil {
		return errors.Wrap(err, "verify consensus message signature")
	} else if !ok {
		return errors.New("invalid consensus message signature")
	}

	return nil
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

func valuesByHash(values []*anypb.Any) (map[[32]byte]*anypb.Any, error) {
	resp := make(map[[32]byte]*anypb.Any)
	for _, v := range values {
		inner, err := v.UnmarshalNew()
		if err != nil {
			return nil, errors.Wrap(err, "unmarshal any")
		}

		hash, err := hashProto(inner)
		if err != nil {
			return nil, err
		}

		resp[hash] = v
	}

	return resp, nil
}
