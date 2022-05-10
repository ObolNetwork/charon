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

package qbft_test

import (
	"context"
	"math"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core/qbft"
)

func TestQBFT(t *testing.T) {
	t.Run("happy 0", func(t *testing.T) {
		testQBFT(t, test{
			Instance:    0,
			StartDelay:  nil,
			DecideRound: 1,
		})
	})

	t.Run("happy 1", func(t *testing.T) {
		testQBFT(t, test{
			Instance:    1,
			StartDelay:  nil,
			DecideRound: 1,
		})
	})

	t.Run("leader late exp", func(t *testing.T) {
		testQBFT(t, test{
			Instance:    0,
			StartDelay:  map[int64]time.Duration{1: time.Second * 2},
			DecideRound: 2,
		})
	})

	t.Run("leader down const", func(t *testing.T) {
		testQBFT(t, test{
			Instance:    0,
			StartDelay:  map[int64]time.Duration{1: time.Second * 2},
			ConstPeriod: true,
			DecideRound: 2,
		})
	})

	t.Run("very late exp", func(t *testing.T) {
		testQBFT(t, test{
			Instance: 3,
			StartDelay: map[int64]time.Duration{
				1: time.Second * 5,
				2: time.Second * 10,
			},
			DecideRound: 4,
		})
	})

	t.Run("very late const", func(t *testing.T) {
		testQBFT(t, test{
			Instance: 1,
			StartDelay: map[int64]time.Duration{
				1: time.Second * 5,
				2: time.Second * 10,
			},
			ConstPeriod: true,
			RandomRound: true,
		})
	})

	t.Run("stagger start exp", func(t *testing.T) {
		testQBFT(t, test{
			Instance: 0,
			StartDelay: map[int64]time.Duration{
				0: time.Second * 0,
				1: time.Second * 1,
				2: time.Second * 2,
				3: time.Second * 3,
			},
			RandomRound: true, // Takes 1 or 2 rounds.
		})
	})

	t.Run("stagger start const", func(t *testing.T) {
		testQBFT(t, test{
			Instance: 0,
			StartDelay: map[int64]time.Duration{
				0: time.Second * 0,
				1: time.Second * 1,
				2: time.Second * 2,
				3: time.Second * 3,
			},
			ConstPeriod: true,
			RandomRound: true, // Takes 1 or 2 rounds.
		})
	})

	t.Run("500ms jitter exp", func(t *testing.T) {
		testQBFT(t, test{
			Instance:      3,
			BCastJitterMS: 500,
			RandomRound:   true,
		})
	})

	t.Run("200ms jitter const", func(t *testing.T) {
		testQBFT(t, test{
			Instance:      3,
			BCastJitterMS: 200, // 0.2-0.4s network delay * 3msgs/round == 0.6-1.2s delay per 1s round.
			ConstPeriod:   true,
			RandomRound:   true,
		})
	})

	t.Run("drop 10% const", func(t *testing.T) {
		testQBFT(t, test{
			Instance: 1,
			DropProb: map[int64]float64{
				0: 0.1,
				1: 0.1,
				2: 0.1,
				3: 0.1,
			},
			ConstPeriod: true,
			RandomRound: true,
		})
	})
}

type test struct {
	Instance      int64                   // Consensus instance, only affects leader election.
	ConstPeriod   bool                    // ConstPeriod results in 1s round timeout, otherwise exponential (1s,2s,4s...)
	StartDelay    map[int64]time.Duration // Delays start of certain processes
	DropProb      map[int64]float64       // DropProb [0..1] probability of dropped messages per processes
	BCastJitterMS int                     // Add random delays to broadcast of messages.
	DecideRound   int                     // Deterministic consensus at specific round
	RandomRound   bool                    // Non-deterministic consensus at random round.
}

//nolint:gocognit
func testQBFT(t *testing.T, test test) {
	t.Helper()

	const n = 4

	var (
		ctx, cancel = context.WithCancel(context.Background())
		clock       = new(fakeClock)
		receives    = make(map[int64]chan qbft.Msg[int64, value])
		broadcast   = make(chan qbft.Msg[int64, value])
		resultChan  = make(chan []qbft.Msg[int64, value], n)
		errChan     = make(chan error, n)
	)
	defer cancel()

	defs := qbft.Definition[int64, value]{
		IsLeader: func(instance int64, round int64, process int64) bool {
			return (instance+round)%n == process
		},
		NewTimer: func(round int64) (<-chan time.Time, func()) {
			d := time.Second
			if !test.ConstPeriod { // If not constant periods, then exponential.
				d = time.Duration(math.Pow(2, float64(round-1))) * time.Second
			}

			return clock.NewTimer(d)
		},
		Decide: func(instance int64, value value, qcommit []qbft.Msg[int64, value]) {
			resultChan <- qcommit
		},
		LogUponRule: func(instance int64, process, round int64, msg qbft.Msg[int64, value], rule string) {
			t.Logf("%s %d => %v@%d -> %v@%d ~= %v", clock.NowStr(), msg.Source(), msg.Type(), msg.Round(), process, round, rule)
			if round > 50 {
				cancel()
			} else if strings.Contains(rule, "Unjust") {
				t.Logf("%s: %#v", rule, msg)
				cancel()
			}
		},
		Nodes: n,
	}

	for i := int64(1); i <= n; i++ {
		receive := make(chan qbft.Msg[int64, value], 1000)
		receives[i] = receive
		trans := qbft.Transport[int64, value]{
			Broadcast: func(typ qbft.MsgType, instance int64, source int64, round int64, value value,
				pr int64, pv value, justify []qbft.Msg[int64, value],
			) {
				msg := newMsg(typ, instance, source, round, value, pr, pv, justify)
				receive <- msg // Always send to self first (no jitter, no drops).
				bcast(broadcast, msg, test.BCastJitterMS, clock)
			},
			SendQCommit: func(_ int64, qCommit []qbft.Msg[int64, value]) {
				for _, msg := range qCommit {
					broadcast <- msg // Just broadcast
				}
			},
			Receive: receive,
		}

		go func(i int64) {
			if d, ok := test.StartDelay[i]; ok {
				ch, _ := clock.NewTimer(d)
				<-ch

				// Drain any buffered messages
				for {
					select {
					case <-receive:
						continue
					default:
					}

					break
				}
			}

			err := qbft.Run(ctx, defs, trans, test.Instance, i, value(i))
			if err != nil {
				errChan <- err
				return
			}
		}(i)
	}

	results := make(map[int64]qbft.Msg[int64, value])
	var count int

	for {
		select {
		case msg := <-broadcast:
			t.Logf("%s %v => %v@%d", clock.NowStr(), msg.Source(), msg.Type(), msg.Round())
			for target, out := range receives {
				if target == msg.Source() {
					continue // Do not broadcast to self, we sent to self already.
				}
				if p, ok := test.DropProb[msg.Source()]; ok {
					if rand.Float64() < p {
						continue // Drop
					}
				}
				out <- msg
				if rand.Float64() < 0.1 { // Send 10% messages twice
					out <- msg
				}
			}
		case qCommit := <-resultChan:
			for _, commit := range qCommit {
				// Ensure that all results are the same
				for _, previous := range results {
					require.EqualValues(t, previous.Value(), commit.Value())
				}
				if !test.RandomRound {
					require.EqualValues(t, test.DecideRound, commit.Round())
				}
				results[commit.Source()] = commit
			}

			count++
			if count == n {
				round := qCommit[0].Round()
				t.Logf("Got all results in round %d after %s: %#v", round, clock.SinceT0(), results)

				return
			}
		case err := <-errChan:
			require.Fail(t, err.Error())
		default:
			time.Sleep(time.Microsecond)
			clock.Advance(time.Millisecond * 1)
		}
	}
}

// bcast delays the message broadcast by between 1x and 2x jitterMS and drops messages.
func bcast[I any, V qbft.Value[V]](broadcast chan qbft.Msg[I, V], msg qbft.Msg[I, V], jitterMS int, clock *fakeClock) {
	if jitterMS == 0 {
		broadcast <- msg

		return
	}

	go func() {
		deltaMS := int(float64(jitterMS) * rand.Float64())
		ch, _ := clock.NewTimer(time.Duration(jitterMS+deltaMS) * time.Millisecond)
		<-ch
		broadcast <- msg
	}()
}

// newMsg returns a new message to be broadcast.
func newMsg(typ qbft.MsgType, instance int64, source int64, round int64, value value,
	pr int64, pv value, justify []qbft.Msg[int64, value],
) qbft.Msg[int64, value] {
	var msgs []msg
	for _, j := range justify {
		m := j.(msg)
		msgs = append(msgs, m)
	}

	return msg{
		msgType:  typ,
		instance: instance,
		peerIdx:  source,
		round:    round,
		value:    int64(value),
		pr:       pr,
		pv:       int64(pv),
		justify:  msgs,
	}
}

var _ qbft.Msg[int64, value] = msg{}

type msg struct {
	msgType  qbft.MsgType
	instance int64
	peerIdx  int64
	round    int64
	value    int64
	pr       int64
	pv       int64
	justify  []msg
}

func (m msg) Type() qbft.MsgType {
	return m.msgType
}

func (m msg) Instance() int64 {
	return m.instance
}

func (m msg) Source() int64 {
	return m.peerIdx
}

func (m msg) Round() int64 {
	return m.round
}

func (m msg) Value() value {
	return value(m.value)
}

func (m msg) PreparedRound() int64 {
	return m.pr
}

func (m msg) PreparedValue() value {
	return value(m.pv)
}

func (m msg) Justification() []qbft.Msg[int64, value] {
	var resp []qbft.Msg[int64, value]
	for _, msg := range m.justify {
		resp = append(resp, msg)
	}

	return resp
}

var _ qbft.Value[value] = value(0)

type value int64

func (v value) Equal(v2 value) bool {
	return int64(v) == int64(v2)
}

func TestFormulas(t *testing.T) {
	// assert given N asserts Q and F.
	assert := func(t *testing.T, n, q, f int) {
		t.Helper()
		d := qbft.Definition[any, value]{Nodes: n}
		require.Equalf(t, q, d.Quorum(), "Quorum given N=%d", n)
		require.Equalf(t, f, d.Faulty(), "Faulty given N=%d", n)
	}

	assert(t, 1, 1, 0)
	assert(t, 2, 2, 0)
	assert(t, 3, 2, 0)
	assert(t, 4, 3, 1)
	assert(t, 5, 4, 1)
	assert(t, 6, 4, 1)
	assert(t, 7, 5, 2)
	assert(t, 8, 6, 2)
	assert(t, 9, 6, 2)
	assert(t, 10, 7, 3)
	assert(t, 11, 8, 3)
	assert(t, 12, 8, 3)
	assert(t, 13, 9, 4)
	assert(t, 15, 10, 4)
	assert(t, 17, 12, 5)
	assert(t, 19, 13, 6)
	assert(t, 21, 14, 6)
}
