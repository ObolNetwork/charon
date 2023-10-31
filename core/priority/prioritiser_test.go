// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package priority_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

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
	)

	// Create libp2p tcp nodes.
	for i := 0; i < n; i++ {
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
	for i := 0; i < n; i++ {
		tcpNode := tcpNodes[i]

		// Propose 0:[0], 1:[0,1], 2:[0,1,2] - expect [0]
		var priorities []*anypb.Any
		for j := 0; j <= i; j++ {
			priorities = append(priorities, prioToAny(j))
		}

		prio := priority.NewForT(t, tcpNode, peers, n, p2p.SendReceive, p2p.RegisterHandler,
			consensus, msgValidator, time.Hour, deadliner)

		prio.Subscribe(func(_ context.Context, duty core.Duty, result *pbv1.PriorityResult) error {
			require.Len(t, result.Topics, 1)

			resTopic, err := result.Topics[0].Topic.UnmarshalNew()
			require.NoError(t, err)

			requireAnyDuty(t, duties, duty)
			requireProtoEqual(t, topic, resTopic)
			results <- result.Topics[0].Priorities

			return nil
		})

		for _, duty := range duties {
			msg := &pbv1.PriorityMsg{
				Topics: []*pbv1.PriorityTopicProposal{{Topic: mustAny(topic), Priorities: priorities}},
				Duty:   core.DutyToProto(duty),
				PeerId: tcpNode.ID().String(),
			}
			go func() {
				require.ErrorIs(t, prio.Prioritise(ctx, msg), context.Canceled)
			}()
		}
	}

	for i := 0; i < n*len(duties); i++ {
		res := <-results
		require.Len(t, res, 1)
		require.EqualValues(t, n*1000, res[0].Score)
		requireProtoEqual(t, prioToAny(0), res[0].Priority)
	}

	cancel()
}

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
		prev := mustResultsToText(t.proposed[duty.Slot].Topics)
		this := mustResultsToText(result.Topics)
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
	for _, msg := range anyOf {
		if msg == actual {
			return
		}
	}
	require.Fail(t, "not anyOf: %#v\nactual: %#v\n", anyOf, actual)
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
