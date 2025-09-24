// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package qbft

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/tracer"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus/instance"
	"github.com/obolnetwork/charon/core/consensus/metrics"
	"github.com/obolnetwork/charon/core/consensus/protocols"
	"github.com/obolnetwork/charon/core/consensus/timer"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/qbft"
	"github.com/obolnetwork/charon/p2p"
)

type subscriber func(ctx context.Context, duty core.Duty, value proto.Message) error

var supportedCompareDuties = []core.DutyType{core.DutyAttester}

// newDefinition returns a qbft definition (this is constant across all consensus instances).
func newDefinition(nodes int, subs func() []subscriber, roundTimer timer.RoundTimer,
	decideCallback func(qcommit []qbft.Msg[core.Duty, [32]byte, proto.Message]), compareAttestations bool,
) qbft.Definition[core.Duty, [32]byte, proto.Message] {
	quorum := qbft.Definition[core.Duty, [32]byte, proto.Message]{Nodes: nodes}.Quorum()

	return qbft.Definition[core.Duty, [32]byte, proto.Message]{
		// IsLeader is a deterministic leader election function.
		IsLeader: func(duty core.Duty, round, process int64) bool {
			return leader(duty, round, nodes) == process
		},

		// Decide sends consensus output to subscribers.
		Decide: func(ctx context.Context, duty core.Duty, _ [32]byte, qcommit []qbft.Msg[core.Duty, [32]byte, proto.Message]) {
			msg, ok := qcommit[0].(Msg)
			if !ok {
				log.Error(ctx, "Invalid message type", nil)
				return
			}

			anyValue, ok := msg.Values()[msg.Value()]
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

		Compare: func(ctx context.Context, msg qbft.Msg[core.Duty, [32]byte, proto.Message], inputValueSourceCh <-chan proto.Message, inputValueSource proto.Message, returnErrCh chan error, returnProtoCh chan proto.Message) {
			if !compareAttestations {
				returnErrCh <- nil
				return
			}

			if !slices.Contains(supportedCompareDuties, msg.Instance().Type) {
				returnErrCh <- nil
				return
			}

			attLeaderAnyPbProto, err := msg.ValueSource()
			if err != nil {
				returnErrCh <- errors.Wrap(err, "msg has no value source", z.Any("msg", msg))
				return
			}

			attLeaderAnyPb, ok := attLeaderAnyPbProto.(*anypb.Any)
			if !ok {
				returnErrCh <- errors.New("protoMessage interface to *anypb.Any struct", z.Any("attLeaderAnyPbProto", attLeaderAnyPbProto))
				return
			}

			attLeaderSetProto, err := attLeaderAnyPb.UnmarshalNew()
			if err != nil {
				returnErrCh <- errors.Wrap(err, "unmarshal *anypb.Any", z.Any("attLeaderAnyPb", attLeaderAnyPb))
				return
			}

			attLeaderSet, ok := attLeaderSetProto.(*pbv1.UnsignedDataSet)
			if !ok {
				returnErrCh <- errors.New("protoMessage interface to *pbv1.UnsignedDataSet struct", z.Any("attLeaderSetProto", attLeaderSetProto))
				return
			}

			switch msg.Instance().Type {
			case core.DutyAttester:
				if inputValueSource == nil {
					select {
					case <-ctx.Done():
						returnErrCh <- errors.New("timeout on waiting for local value")
						return
					case inputValueSource = <-inputValueSourceCh:
						returnProtoCh <- inputValueSource
					}
				}

				attLocalSet, ok := inputValueSource.(*pbv1.UnsignedDataSet)
				if !ok {
					returnErrCh <- errors.New("inputValueSource to pbv1.UnsignedDataSet")
					return
				}

				err = attestationChecker(ctx, attLeaderSet, attLocalSet)
				if err != nil {
					returnErrCh <- errors.Wrap(err, "attestation checker failed")
					return
				}
			default:
				returnErrCh <- errors.New("bug: checking not supported duty", z.Any("duty", msg.Instance().Type))
				return
			}
			returnErrCh <- nil
		},

		NewTimer: roundTimer.Timer,

		// LogUponRule logs upon rules at debug level.
		LogUponRule: func(ctx context.Context, _ core.Duty, _, round int64,
			_ qbft.Msg[core.Duty, [32]byte, proto.Message], uponRule qbft.UponRule,
		) {
			log.Debug(ctx, "QBFT upon rule triggered", z.Any("rule", uponRule), z.I64("round", round))
		},

		// LogRoundChange logs round changes at debug level.
		LogRoundChange: func(ctx context.Context, duty core.Duty, process, round, newRound int64, //nolint:revive // keep process variable name for clarity
			uponRule qbft.UponRule, msgs []qbft.Msg[core.Duty, [32]byte, proto.Message],
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

		LogUnjust: func(ctx context.Context, _ core.Duty, _ int64, msg qbft.Msg[core.Duty, [32]byte, proto.Message]) {
			log.Warn(ctx, "Unjustified consensus message from peer", nil,
				z.Any("type", msg.Type()),
				z.I64("peer", msg.Source()),
			)
		},

		// Nodes is the number of nodes.
		Nodes: nodes,

		// FIFOLimit caps the max buffered messages per peer.
		FIFOLimit: instance.RecvBufferSize,
	}
}

func attestationChecker(ctx context.Context, attLeaderSet *pbv1.UnsignedDataSet, attLocalSet *pbv1.UnsignedDataSet) error {
	attLocalSetCore, err := core.UnsignedDataSetFromProto(core.DutyAttester, attLocalSet)
	if err != nil {
		return errors.Wrap(err, "attLocal to unsigned data set duty attester")
	}

	attLeaderSetCore, err := core.UnsignedDataSetFromProto(core.DutyAttester, attLeaderSet)
	if err != nil {
		return errors.Wrap(err, "attLeader to unsigned data set duty attester")
	}

	for attLeaderKey, attLeaderData := range attLeaderSetCore {
		attLocalData, ok := attLocalSetCore[attLeaderKey]
		if !ok {
			log.Warn(ctx, "", errors.New("no local attestation found, skipping"), z.Any("pk", attLeaderKey))
			continue
		}

		attLeaderAttestationData, ok := attLeaderData.(core.AttestationData)
		if !ok {
			return errors.New("unable to parse leader unsigned data to core attestation data", z.Any("data", attLeaderData))
		}

		attLocalAttestationData, ok := attLocalData.(core.AttestationData)
		if !ok {
			return errors.New("unable to parse local unsigned data to core attestation data", z.Any("data", attLocalData))
		}

		mismatch := ""
		if attLeaderAttestationData.Data.Source.Epoch != attLocalAttestationData.Data.Source.Epoch {
			mismatch += "leader attestation source epoch differs from local source epoch;"
		}

		if attLeaderAttestationData.Data.Source.Root != attLocalAttestationData.Data.Source.Root {
			mismatch += "leader attestation source root differs from local source root;"
		}

		if attLeaderAttestationData.Data.Target.Epoch != attLocalAttestationData.Data.Target.Epoch {
			mismatch += "leader attestation target epoch differs from local target epoch;"
		}

		if attLeaderAttestationData.Data.Target.Root != attLocalAttestationData.Data.Target.Root {
			mismatch += "leader attestation target root differs from local target root;"
		}

		if mismatch != "" {
			return errors.New(mismatch, z.Any("public_key", attLeaderKey), z.Any("leader", attLeaderAttestationData.Data), z.Any("local", attLocalAttestationData.Data))
		}
	}

	return nil
}

// NewConsensus returns a new consensus QBFT component.
func NewConsensus(p2pNode host.Host, sender *p2p.Sender, peers []p2p.Peer, p2pKey *k1.PrivateKey,
	deadliner core.Deadliner, gaterFunc core.DutyGaterFunc, snifferFunc func(*pbv1.SniffedConsensusInstance), compareAttestations bool,
) (*Consensus, error) {
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

	c := &Consensus{
		p2pNode:             p2pNode,
		sender:              sender,
		peers:               peers,
		peerLabels:          labels,
		privkey:             p2pKey,
		pubkeys:             keys,
		deadliner:           deadliner,
		snifferFunc:         snifferFunc,
		gaterFunc:           gaterFunc,
		dropFilter:          log.Filter(),
		timerFunc:           timer.GetRoundTimerFunc(),
		metrics:             metrics.NewConsensusMetrics(protocols.QBFTv2ProtocolID),
		compareAttestations: compareAttestations,
	}
	c.mutable.instances = make(map[core.Duty]*instance.IO[Msg])

	return c, nil
}

// Consensus implements core.Consensus & priority.coreConsensus.
type Consensus struct {
	// Immutable state
	p2pNode             host.Host
	sender              *p2p.Sender
	peerLabels          []string
	peers               []p2p.Peer
	pubkeys             map[int64]*k1.PublicKey
	privkey             *k1.PrivateKey
	subs                []subscriber
	deadliner           core.Deadliner
	snifferFunc         func(*pbv1.SniffedConsensusInstance)
	gaterFunc           core.DutyGaterFunc
	dropFilter          z.Field // Filter buffer overflow errors (possible DDoS)
	timerFunc           timer.RoundTimerFunc
	metrics             metrics.ConsensusMetrics
	compareAttestations bool

	// Mutable state
	mutable struct {
		sync.Mutex

		instances map[core.Duty]*instance.IO[Msg]
	}
}

// ProtocolID returns the protocol ID.
func (*Consensus) ProtocolID() protocol.ID {
	return protocols.QBFTv2ProtocolID
}

// Subscribe registers a callback for unsigned duty data proposals from leaders.
// Note this function is not thread safe, it should be called *before* Start and Propose.
func (c *Consensus) Subscribe(fn func(ctx context.Context, duty core.Duty, set core.UnsignedDataSet) error) {
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
func (c *Consensus) subscribers() []subscriber {
	return c.subs
}

// SubscribePriority registers a callback for priority protocol message proposals from leaders.
// Note this function is not thread safe, it should be called *before* Start and Propose.
func (c *Consensus) SubscribePriority(fn func(ctx context.Context, duty core.Duty, msg *pbv1.PriorityResult) error) {
	c.subs = append(c.subs, func(ctx context.Context, duty core.Duty, value proto.Message) error {
		msg, ok := value.(*pbv1.PriorityResult)
		if !ok {
			return nil
		}

		return fn(ctx, duty, msg)
	})
}

// Start registers libp2p handler and runs internal routines until the context is cancelled.
func (c *Consensus) Start(ctx context.Context) {
	p2p.RegisterHandler("qbft", c.p2pNode, protocols.QBFTv2ProtocolID,
		func() proto.Message { return new(pbv1.QBFTConsensusMsg) },
		c.handle)

	go func() {
		for {
			select {
			case <-ctx.Done():
				// No need to unregister QBFT handler.
				return
			case duty := <-c.deadliner.C():
				c.deleteInstanceIO(duty)
			}
		}
	}()
}

// Propose enqueues the proposed value to a consensus instance input channels.
// It either runs the consensus instance if it is not already running or
// waits until it completes, in both cases it returns the resulting error.
// Note this errors if called multiple times for the same duty.
func (c *Consensus) Propose(ctx context.Context, duty core.Duty, data core.UnsignedDataSet) error {
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
// Note this errors if called multiple times for the same duty.
func (c *Consensus) ProposePriority(ctx context.Context, duty core.Duty, msg *pbv1.PriorityResult) error {
	return c.propose(ctx, duty, msg)
}

// propose enqueues the proposed value to a consensus instance input channels.
// It either runs the consensus instance if it is not already running or
// waits until it completes, in both cases it returns the resulting error.
// Note this errors if called multiple times for the same duty.
func (c *Consensus) propose(ctx context.Context, duty core.Duty, value proto.Message) error {
	hash, err := hashProto(value)
	if err != nil {
		return err
	}

	inst := c.getInstanceIO(duty)

	if err := inst.MarkProposed(); err != nil {
		return errors.Wrap(err, "propose consensus", z.Any("duty", duty))
	}

	// Provide proposal inputs to the instance.
	select {
	case inst.ValueCh <- value:
	default:
		return errors.New("input channel full")
	}

	select {
	case inst.HashCh <- hash:
	default:
		return errors.New("input channel full")
	}

	if c.compareAttestations {
		select {
		case inst.VerifyCh <- value:
		default:
			return errors.New("input channel full")
		}
	}

	// Instrument consensus duration using decidedAt output.
	proposedAt := time.Now()

	defer func() {
		select {
		case decidedAt := <-inst.DecidedAtCh:
			timerType := c.timerFunc(duty).Type()
			duration := decidedAt.Sub(proposedAt)
			c.metrics.ObserveConsensusDuration(duty.Type.String(), string(timerType), duration.Seconds())
		default:
		}
	}()

	if !inst.MaybeStart() { // Participate was already called, instance is running.
		return <-inst.ErrCh
	}

	return c.runInstance(ctx, duty)
}

// Participate runs a new a consensus instance to participate while still waiting for
// unsigned data from beacon node and Propose not already called.
// Note Propose must still be called for this peer to propose a value when leading a round.
// Note this errors if called multiple times for the same duty.
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

// Broadcast implements Broadcaster interface.
func (c *Consensus) Broadcast(ctx context.Context, msg *pbv1.QBFTConsensusMsg) error {
	for _, peer := range c.peers {
		if peer.ID == c.p2pNode.ID() {
			// Do not broadcast to self
			continue
		}

		if err := c.sender.SendAsync(ctx, c.p2pNode, protocols.QBFTv2ProtocolID, peer.ID, msg); err != nil {
			return err
		}
	}

	return nil
}

// runInstance blocks and runs a consensus instance for the given duty.
// It returns an error or nil when the context is cancelled.
// Note each instance may only be run once.
func (c *Consensus) runInstance(parent context.Context, duty core.Duty) (err error) {
	roundTimer := c.timerFunc(duty)
	ctx := log.WithTopic(parent, "qbft")
	ctx = log.WithCtx(ctx, z.Any("duty", duty))

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	log.Debug(ctx, "QBFT consensus instance starting",
		z.Any("peer", p2p.PeerName(c.p2pNode.ID())),
		z.Any("peers", c.peerLabels),
		z.Any("timer", string(roundTimer.Type())),
	)

	inst := c.getInstanceIO(duty)

	defer func() {
		inst.ErrCh <- err // Send resulting error to errCh.
	}()

	if !c.deadliner.Add(duty) {
		log.Warn(ctx, "Skipping consensus for expired duty", nil)
		return nil
	}

	peerIdx, err := c.getPeerIdx()
	if err != nil {
		return err
	}

	var (
		decided bool
		nodes   = len(c.peers)
		span    trace.Span
	)

	_, span = tracer.Start(ctx, "qbft.runInstance")
	span.SetAttributes(attribute.String("duty", duty.Type.String()))

	defer func() {
		if err != nil && !isContextErr(err) {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		} else {
			span.SetStatus(codes.Ok, "")
		}

		span.End()
	}()

	decideCallback := func(qcommit []qbft.Msg[core.Duty, [32]byte, proto.Message]) {
		round := qcommit[0].Round()
		decided = true

		inst.DecidedAtCh <- time.Now()

		leaderIndex := leader(duty, round, nodes)
		leaderName := c.peers[leaderIndex].Name
		log.Debug(ctx, "QBFT consensus decided",
			z.Str("duty", duty.Type.String()),
			z.U64("slot", duty.Slot),
			z.I64("round", round),
			z.I64("leader_index", leaderIndex),
			z.Str("leader_name", leaderName))

		c.metrics.SetDecidedLeaderIndex(duty.Type.String(), leaderIndex)
		c.metrics.SetDecidedRounds(duty.Type.String(), string(roundTimer.Type()), round)

		span.SetAttributes(attribute.Int64("round", round))
		span.SetAttributes(attribute.Int64("leader_index", leaderIndex))
		span.SetAttributes(attribute.String("leader_name", leaderName))
		span.AddEvent("qbft.Decided")

		// qbft.Run() is stopped by cancelling the context, or if an error occurred.
		cancel()
	}

	// Create a new qbft definition for this instance.
	def := newDefinition(len(c.peers), c.subscribers, roundTimer, decideCallback, c.compareAttestations)

	// Create a new transport that handles sending and receiving for this instance.
	t := newTransport(c, c.privkey, inst.ValueCh, make(chan qbft.Msg[core.Duty, [32]byte, proto.Message]), newSniffer(int64(def.Nodes), peerIdx))

	// Provide sniffed buffer to snifferFunc at the end.
	defer func() {
		c.snifferFunc(t.SnifferInstance())
	}()

	// Start a receiving goroutine.
	go t.ProcessReceives(ctx, c.getRecvBuffer(duty))

	// Create a qbft transport from the transport
	qt := qbft.Transport[core.Duty, [32]byte, proto.Message]{
		Broadcast: t.Broadcast,
		Receive:   t.RecvBuffer(),
	}

	// Run the algo, blocking until the context is cancelled.
	err = qbft.Run(ctx, def, qt, duty, peerIdx, inst.HashCh, inst.VerifyCh)
	if err != nil && !isContextErr(err) {
		span.AddEvent("qbft.Error")
		c.metrics.IncConsensusError()

		return err // Only return non-context errors.
	}

	if !decided {
		span.AddEvent("qbft.Timeout")
		c.metrics.IncConsensusTimeout(duty.Type.String(), string(roundTimer.Type()))

		return errors.New("consensus timeout", z.Str("duty", duty.String()))
	}

	return nil
}

// handle processes an incoming consensus wire message.
func (c *Consensus) handle(ctx context.Context, _ peer.ID, req proto.Message) (proto.Message, bool, error) {
	t0 := time.Now()

	pbMsg, ok := req.(*pbv1.QBFTConsensusMsg)
	if !ok || pbMsg == nil {
		return nil, false, errors.New("invalid consensus message")
	}

	if err := verifyMsg(pbMsg.GetMsg(), c.pubkeys); err != nil {
		return nil, false, err
	}

	duty := core.DutyFromProto(pbMsg.GetMsg().GetDuty())
	ctx = log.WithCtx(ctx, z.Any("duty", duty))

	if !c.gaterFunc(duty) {
		return nil, false, errors.New("invalid duty", z.Any("duty", duty))
	}

	for _, justification := range pbMsg.GetJustification() {
		if err := verifyMsg(justification, c.pubkeys); err != nil {
			return nil, false, errors.Wrap(err, "invalid justification")
		}

		justDuty := core.DutyFromProto(justification.GetDuty())
		if justDuty != duty {
			return nil, false, errors.New(
				"qbft justification duty differs from message duty",
				z.Str("expected", duty.String()),
				z.Str("found", justDuty.String()),
			)
		}
	}

	values, err := valuesByHash(pbMsg.GetValues())
	if err != nil {
		return nil, false, err
	}

	msg, err := newMsg(pbMsg.GetMsg(), pbMsg.GetJustification(), values)
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
func (c *Consensus) getRecvBuffer(duty core.Duty) chan Msg {
	c.mutable.Lock()
	defer c.mutable.Unlock()

	inst, ok := c.mutable.instances[duty]
	if !ok {
		inst = instance.NewIO[Msg]()
		c.mutable.instances[duty] = inst
	}

	return inst.RecvBuffer
}

// getInstanceIO returns the duty's instance if it were previously created.
func (c *Consensus) getInstanceIO(duty core.Duty) *instance.IO[Msg] {
	c.mutable.Lock()
	defer c.mutable.Unlock()

	inst, ok := c.mutable.instances[duty]
	if !ok { // Create new instanceIO.
		inst = instance.NewIO[Msg]()
		c.mutable.instances[duty] = inst
	}

	return inst
}

// deleteInstanceIO deletes the instanceIO for the duty.
func (c *Consensus) deleteInstanceIO(duty core.Duty) {
	c.mutable.Lock()
	defer c.mutable.Unlock()

	delete(c.mutable.instances, duty)
}

// getPeerIdx returns the local peer index.
func (c *Consensus) getPeerIdx() (int64, error) {
	peerIdx := int64(-1)

	for i, p := range c.peers {
		if c.p2pNode.ID() == p.ID {
			peerIdx = int64(i)
		}
	}

	if peerIdx == -1 {
		return 0, errors.New("local libp2p host not in peer list")
	}

	return peerIdx, nil
}

func verifyMsg(msg *pbv1.QBFTMsg, pubkeys map[int64]*k1.PublicKey) error {
	if msg == nil || msg.GetDuty() == nil {
		return errors.New("invalid consensus message")
	}

	if typ := qbft.MsgType(msg.GetType()); !typ.Valid() {
		return errors.New("invalid consensus message type", z.Int("type", int(typ)))
	}

	if typ := core.DutyType(msg.GetDuty().GetType()); !typ.Valid() {
		return errors.New("invalid consensus message duty type", z.Int("type", int(typ)))
	}

	if msg.GetRound() <= 0 {
		return errors.New("invalid consensus message round", z.I64("round", msg.GetRound()))
	}

	if msg.GetPreparedRound() < 0 {
		return errors.New("invalid consensus message prepared round")
	}

	msgPubkey, exists := pubkeys[msg.GetPeerIdx()]
	if !exists {
		return errors.New("invalid peer index", z.I64("index", msg.GetPeerIdx()))
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

// roundStep groups consensus round messages by type and peer status.
type roundStep struct {
	Type    qbft.MsgType
	Present []int
	Missing []int
	Peers   int
}

// groupRoundMessages groups messages by type and returns which peers were present and missing for each type.
func groupRoundMessages(msgs []qbft.Msg[core.Duty, [32]byte, proto.Message], peers int, round int64, leader int) []roundStep {
	// checkPeers returns two slices of peer indexes, one with peers
	// present with the message type and one with messing peers.
	checkPeers := func(typ qbft.MsgType) (present []int, missing []int) {
		for i := range peers {
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
	for range step.Peers {
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
	return (int64(duty.Slot) + int64(duty.Type) + round) % int64(nodes)
}

// valuesByHash returns a map of values by hash.
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
