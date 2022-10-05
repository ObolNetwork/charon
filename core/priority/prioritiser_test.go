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

package priority_test

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/priority"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestPrioritiser(t *testing.T) {
	var (
		ctx, cancel  = context.WithCancel(context.Background())
		n            = 3
		slot         = int64(99)
		tcpNodes     []host.Host
		peers        []peer.ID
		consensus    = new(testConsensus)
		msgValidator = func(*pbv1.PriorityMsg) error { return nil }
		noTicks      = func() (<-chan time.Time, func()) { return nil, func() {} }
		results      = make(chan []*pbv1.PriorityScoredResult, n)
		topic        = "test"
	)

	// Create libp2p tcp nodes.
	for i := 0; i < n; i++ {
		tcpNode := testutil.CreateHost(t, testutil.AvailableAddr(t))
		for _, other := range tcpNodes {
			tcpNode.Peerstore().AddAddrs(other.ID(), other.Addrs(), peerstore.PermanentAddrTTL)
			other.Peerstore().AddAddrs(tcpNode.ID(), tcpNode.Addrs(), peerstore.PermanentAddrTTL)
		}
		tcpNodes = append(tcpNodes, tcpNode)
		peers = append(peers, tcpNode.ID())
	}

	// Create prioritisers
	for i := 0; i < n; i++ {
		tcpNode := tcpNodes[i]

		// Propose 0:[0], 1:[0,1], 2:[0,1,2] - expect [0]
		var labels []string
		for j := 0; j <= i; j++ {
			labels = append(labels, fmt.Sprint(j))
		}
		msgProvider := func(slot int64) (*pbv1.PriorityMsg, error) {
			return &pbv1.PriorityMsg{
				Topics: []*pbv1.PriorityTopicProposal{{Topic: topic, Priorities: labels}},
				Slot:   slot,
				PeerId: tcpNode.ID().String(),
			}, nil
		}

		prio := priority.NewForT(tcpNode, peers, n, p2p.SendReceive, p2p.RegisterHandler, consensus,
			msgProvider, msgValidator, time.Hour, noTicks)

		prio.Subscribe(topic, func(_ context.Context, slotRes int64, topicRes string, priorities []*pbv1.PriorityScoredResult) error {
			require.Equal(t, slot, slotRes)
			require.Equal(t, topic, topicRes)
			results <- priorities

			return nil
		})

		go func() {
			require.ErrorIs(t, prio.Run(ctx), context.Canceled)
		}()

		go func() {
			prio.Prioritise(slot)
		}()
	}

	expect := []*pbv1.PriorityScoredResult{{
		Priority: "0",
		Score:    int64(n * 1000),
	}}
	for i := 0; i < n; i++ {
		res := <-results
		require.Equal(t, expect, res)
	}

	cancel()
}

// testConsensus is a mock consensus implementation that "decides" on the first proposal.
// It also expects all proposals to be identical.
type testConsensus struct {
	mu       sync.Mutex
	proposed *pbv1.PriorityResult
	subs     []func(ctx context.Context, slot int64, result *pbv1.PriorityResult) error
}

func (t *testConsensus) ProposePriority(ctx context.Context, slot int64, result *pbv1.PriorityResult) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.proposed != nil {
		if !reflect.DeepEqual(t.proposed, result) {
			return errors.New("mismatching proposals")
		}

		return nil
	}

	for _, sub := range t.subs {
		err := sub(ctx, slot, result)
		if err != nil {
			return err
		}
	}
	t.proposed = result

	return nil
}

func (t *testConsensus) SubscribePriority(sub func(ctx context.Context, slot int64, result *pbv1.PriorityResult) error) {
	t.subs = append(t.subs, sub)
}
