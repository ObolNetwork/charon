// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package priority_test

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/priority"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestPrioritiser(t *testing.T) {
	var (
		ctx, cancel  = context.WithCancel(context.Background())
		n            = 3
		duties       = []core.Duty{{Slot: 97}, {Slot: 98}, {Slot: 99}}
		tcpNodes     []host.Host
		peers        []peer.ID
		consensus    = &testConsensus{t: t}
		msgValidator = func(*pbv1.PriorityMsg) error { return nil }
		results      = make(chan []*pbv1.PriorityScoredResult, n)
		topic        = &pbv1.ParSignedData{Data: []byte("test topic")}
		deadliner    = core.NewDeadliner(ctx, "", func(core.Duty) (time.Time, bool) {
			return time.Now().Add(time.Hour), true
		})
		errCh = make(chan error, len(duties))
	)

	// Create libp2p tcp nodes.
	for range n {
		tcpNode := testutil.CreateHost(t, testutil.AvailableAddr(t))
		for _, other := range tcpNodes {
			tcpNode.Peerstore().AddAddrs(other.ID(), other.Addrs(), peerstore.PermanentAddrTTL)
			other.Peerstore().AddAddrs(tcpNode.ID(), tcpNode.Addrs(), peerstore.PermanentAddrTTL)
			require.NoError(t, tcpNode.Peerstore().AddProtocols(other.ID(), priority.Protocols()...))
			require.NoError(t, other.Peerstore().AddProtocols(tcpNode.ID(), priority.Protocols()...))
		}

		tcpNodes = append(tcpNodes, tcpNode)
		peers = append(peers, tcpNode.ID())
	}

	// Create prioritisers
	for i := range n {
		tcpNode := tcpNodes[i]

		// Propose 0:[0], 1:[0,1], 2:[0,1,2] - expect [0]
		var priorities []*anypb.Any
		for j := range i + 1 {
			priorities = append(priorities, prioToAny(j))
		}

		prio := priority.NewForT(t, tcpNode, peers, n, p2p.SendReceive, p2p.RegisterHandler,
			consensus, msgValidator, time.Hour, deadliner, allowAllDuties)

		prio.Subscribe(func(_ context.Context, duty core.Duty, result *pbv1.PriorityResult) error {
			require.Len(t, result.GetTopics(), 1)

			resTopic, err := result.GetTopics()[0].GetTopic().UnmarshalNew()
			require.NoError(t, err)

			requireAnyDuty(t, duties, duty)
			requireProtoEqual(t, topic, resTopic)

			results <- result.GetTopics()[0].GetPriorities()

			return nil
		})

		for _, duty := range duties {
			msg := &pbv1.PriorityMsg{
				Topics: []*pbv1.PriorityTopicProposal{{Topic: mustAny(topic), Priorities: priorities}},
				Duty:   core.DutyToProto(duty),
				PeerId: tcpNode.ID().String(),
			}

			go func() {
				err := prio.Prioritise(ctx, msg)
				errCh <- err
			}()
		}
	}

	for range n * len(duties) {
		res := <-results
		require.Len(t, res, 1)
		require.EqualValues(t, n*1000, res[0].GetScore())
		requireProtoEqual(t, prioToAny(0), res[0].GetPriority())
	}

	cancel()

	for range duties {
		err := <-errCh
		require.ErrorIs(t, err, context.Canceled)
	}
}

// Priority protocol IDs as they appear on the wire. These literals must not change:
// legacyProtocol keeps unpatched peers interoperable and is what they dial, while
// slashedProtocol is the normalised ID all other charon protocols already use.
const (
	legacyProtocol  = protocol.ID("charon/priority/2.0.0")
	slashedProtocol = protocol.ID("/charon/priority/2.0.0")
)

func TestProtocols(t *testing.T) {
	// Order matters: it is the negotiation precedence offered to peers.
	require.Equal(t, []protocol.ID{slashedProtocol, legacyProtocol}, priority.Protocols())
}

// TestProtocolNegotiation asserts a patched node prefers the slash-prefixed protocol
// but falls back to the legacy one when the peer only supports that.
func TestProtocolNegotiation(t *testing.T) {
	tests := []struct {
		name       string
		register   p2p.RegisterHandlerFunc
		advertised []protocol.ID // Protocol IDs the listener is expected to advertise.
		expect     protocol.ID   // Protocol ID expected to be negotiated.
	}{
		{
			name:       "patched peer",
			register:   p2p.RegisterHandler,
			advertised: []protocol.ID{slashedProtocol, legacyProtocol},
			expect:     slashedProtocol,
		},
		{
			name:       "unpatched peer",
			register:   registerLegacyOnly,
			advertised: []protocol.ID{legacyProtocol},
			expect:     legacyProtocol,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()

			dialer := testutil.CreateHost(t, testutil.AvailableAddr(t))
			listener := testutil.CreateHost(t, testutil.AvailableAddr(t))
			dialer.Peerstore().AddAddrs(listener.ID(), listener.Addrs(), peerstore.PermanentAddrTTL)

			peers := []peer.ID{dialer.ID(), listener.ID()}
			newTestPrioritiser(t, listener, peers, p2p.SendReceive, test.register,
				&testConsensus{t: t}, newTestDeadliner(ctx))

			// Guard the protocolPrefix trap: registering both IDs via a single
			// RegisterHandler call would advertise the bare wildcard "*" to peers
			// (via libp2p identify) instead of the actual protocol IDs.
			require.Subset(t, listener.Mux().Protocols(), test.advertised)
			require.NotContains(t, listener.Mux().Protocols(), protocol.ID("*"))

			s, err := dialer.NewStream(ctx, listener.ID(), priority.Protocols()...)
			require.NoError(t, err)

			defer s.Close()

			require.Equal(t, test.expect, s.Protocol())
		})
	}
}

// TestPrioritiserLegacyPeer asserts a patched and an unpatched node complete a
// priority exchange, testing each dial direction in isolation. Only one node dials
// per case, since a node can otherwise reach quorum off its peer's inbound request
// and mask a broken dial of its own.
func TestPrioritiserLegacyPeer(t *testing.T) {
	tests := []struct {
		name        string
		patchedSend p2p.SendReceiveFunc
		legacySend  p2p.SendReceiveFunc
	}{
		{
			// Only the patched node dials, so it must fall back to the legacy protocol.
			name:        "patched dials unpatched",
			patchedSend: p2p.SendReceive,
			legacySend:  sendUnreachable,
		},
		{
			// Only the unpatched node dials, so the patched node must serve the legacy protocol.
			name:        "unpatched dials patched",
			patchedSend: sendUnreachable,
			legacySend:  sendLegacyOnly,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var (
				ctx, cancel = context.WithCancel(context.Background())
				n           = 2
				duty        = core.Duty{Slot: 99}
				consensus   = &testConsensus{t: t}
				results     = make(chan []*pbv1.PriorityScoredResult, n)
				topic       = &pbv1.ParSignedData{Data: []byte("test topic")}
				errCh       = make(chan error, n)
			)

			defer cancel()

			patched := testutil.CreateHost(t, testutil.AvailableAddr(t))
			legacy := testutil.CreateHost(t, testutil.AvailableAddr(t))
			peers := []peer.ID{patched.ID(), legacy.ID()}
			deadliner := newTestDeadliner(ctx)

			patched.Peerstore().AddAddrs(legacy.ID(), legacy.Addrs(), peerstore.PermanentAddrTTL)
			legacy.Peerstore().AddAddrs(patched.ID(), patched.Addrs(), peerstore.PermanentAddrTTL)
			// The patched node only ever learns the legacy protocol from its unpatched peer.
			require.NoError(t, patched.Peerstore().AddProtocols(legacy.ID(), legacyProtocol))
			require.NoError(t, legacy.Peerstore().AddProtocols(patched.ID(), priority.Protocols()...))

			nodes := []struct {
				host     host.Host
				send     p2p.SendReceiveFunc
				register p2p.RegisterHandlerFunc
			}{
				{host: patched, send: test.patchedSend, register: p2p.RegisterHandler},
				{host: legacy, send: test.legacySend, register: registerLegacyOnly},
			}

			for _, node := range nodes {
				prio := newTestPrioritiser(t, node.host, peers, node.send, node.register, consensus, deadliner)

				prio.Subscribe(func(_ context.Context, gotDuty core.Duty, result *pbv1.PriorityResult) error {
					require.Equal(t, duty, gotDuty)
					require.Len(t, result.GetTopics(), 1)

					results <- result.GetTopics()[0].GetPriorities()

					return nil
				})

				msg := &pbv1.PriorityMsg{
					Topics: []*pbv1.PriorityTopicProposal{{Topic: mustAny(topic), Priorities: []*anypb.Any{prioToAny(0)}}},
					Duty:   core.DutyToProto(duty),
					PeerId: node.host.ID().String(),
				}

				go func() {
					errCh <- prio.Prioritise(ctx, msg)
				}()
			}

			// Both nodes exchanged and agreed, so the single priority is scored by both.
			// A broken fallback leaves the exchange waiting on the (1h) exchange timeout,
			// so bound the wait rather than hanging until the go test timeout.
			for range n {
				var res []*pbv1.PriorityScoredResult

				select {
				case res = <-results:
				case <-time.After(15 * time.Second):
					require.FailNow(t, "timeout waiting for priority result, protocol fallback likely broken")
				}

				require.Len(t, res, 1)
				require.EqualValues(t, n*1000, res[0].GetScore())
				requireProtoEqual(t, prioToAny(0), res[0].GetPriority())
			}

			cancel()

			for range n {
				require.ErrorIs(t, <-errCh, context.Canceled)
			}
		})
	}
}

// registerLegacyOnly simulates an unpatched node by dropping handler registrations
// for the slash-prefixed protocol. It implements p2p.RegisterHandlerFunc.
func registerLegacyOnly(logTopic string, p2pNode host.Host, pID protocol.ID,
	zeroReq func() proto.Message, handlerFunc p2p.HandlerFunc, opts ...p2p.SendRecvOption,
) {
	if pID == slashedProtocol {
		return
	}

	p2p.RegisterHandler(logTopic, p2pNode, pID, zeroReq, handlerFunc, opts...)
}

// sendLegacyOnly simulates an unpatched node by always dialing the legacy protocol
// and never offering the slash-prefixed one. It implements p2p.SendReceiveFunc.
func sendLegacyOnly(ctx context.Context, p2pNode host.Host, peerID peer.ID,
	req, resp proto.Message, _ protocol.ID, _ ...p2p.SendRecvOption,
) error {
	return p2p.SendReceive(ctx, p2pNode, peerID, req, resp, legacyProtocol)
}

// sendUnreachable simulates a node that cannot dial out, forcing its exchange to
// complete via the peer's inbound request. It implements p2p.SendReceiveFunc.
func sendUnreachable(context.Context, host.Host, peer.ID, proto.Message, proto.Message,
	protocol.ID, ...p2p.SendRecvOption,
) error {
	return errors.New("unreachable")
}

func newTestDeadliner(ctx context.Context) core.Deadliner {
	return core.NewDeadliner(ctx, "", func(core.Duty) (time.Time, bool) {
		return time.Now().Add(time.Hour), true
	})
}

func newTestPrioritiser(t *testing.T, p2pNode host.Host, peers []peer.ID, send p2p.SendReceiveFunc,
	register p2p.RegisterHandlerFunc, consensus *testConsensus, deadliner core.Deadliner,
) *priority.Prioritiser {
	t.Helper()

	return priority.NewForT(t, p2pNode, peers, len(peers), send, register, consensus,
		func(*pbv1.PriorityMsg) error { return nil }, time.Hour, deadliner, allowAllDuties)
}

// allowAllDuties is a core.DutyGaterFunc that gates nothing.
func allowAllDuties(core.Duty) bool { return true }

// testConsensus is a mock consensus implementation that "decides" on the first proposal.
// It also expects all proposals to be identical.
type testConsensus struct {
	t        *testing.T
	mu       sync.Mutex
	proposed map[uint64]*pbv1.PriorityResult
	subs     []func(ctx context.Context, duty core.Duty, result *pbv1.PriorityResult) error
}

func (t *testConsensus) ProposePriority(ctx context.Context, duty core.Duty, result *pbv1.PriorityResult) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.proposed[duty.Slot] != nil {
		prev := mustResultsToText(t.proposed[duty.Slot].GetTopics())
		this := mustResultsToText(result.GetTopics())
		require.Equal(t.t, prev, this)

		return nil
	}

	for _, sub := range t.subs {
		err := sub(ctx, duty, result)
		if err != nil {
			return err
		}
	}

	if t.proposed == nil {
		t.proposed = make(map[uint64]*pbv1.PriorityResult)
	}

	t.proposed[duty.Slot] = result

	return nil
}

func (t *testConsensus) SubscribePriority(sub func(context.Context, core.Duty, *pbv1.PriorityResult) error) {
	t.subs = append(t.subs, sub)
}

func mustAny(pb proto.Message) *anypb.Any {
	resp, err := anypb.New(pb)
	if err != nil {
		panic(err)
	}

	return resp
}

func prioToAny(prio int) *anypb.Any {
	return mustAny(&pbv1.Duty{Slot: uint64(prio)})
}

func requireAnyDuty(t *testing.T, anyOf []core.Duty, actual core.Duty) {
	t.Helper()

	if slices.Contains(anyOf, actual) {
		return
	}

	require.Fail(t, "slice does not contain duty", "not anyOf: %#v\nactual: %#v\n", anyOf, actual)
}

func mustResultsToText(msgs []*pbv1.PriorityTopicResult) string {
	var resp []string
	for _, msg := range msgs {
		resp = append(resp, prototext.Format(msg))
	}

	return strings.Join(resp, ",")
}

func requireProtoEqual(t *testing.T, expect, actual proto.Message) {
	t.Helper()
	require.True(t, proto.Equal(expect, actual), "expected: %#v\nactual: %#v\n", expect, actual)
}
