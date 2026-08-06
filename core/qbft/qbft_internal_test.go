// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package qbft

import (
	"context"
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
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

	t.Run("prepare round 1, decide round 2", func(t *testing.T) {
		testQBFT(t, test{
			Instance:     0,
			CommitsAfter: 1,
			DecideRound:  2,
			PreparedVal:  1,
		})
	})

	t.Run("prepare round 2, decide round 3", func(t *testing.T) {
		testQBFT(t, test{
			Instance:     0,
			CommitsAfter: 2,
			ValueDelay: map[int64]time.Duration{
				1: 2 * time.Second,
			},
			DecideRound: 3,
			PreparedVal: 2,
			ConstPeriod: true,
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
				1: time.Second * 0,
				2: time.Second * 1,
				3: time.Second * 2,
				4: time.Second * 3,
			},
			RandomRound: true, // Takes 1 or 2 rounds.
		})
	})

	t.Run("stagger start const", func(t *testing.T) {
		testQBFT(t, test{
			Instance: 0,
			StartDelay: map[int64]time.Duration{
				1: time.Second * 0,
				2: time.Second * 1,
				3: time.Second * 2,
				4: time.Second * 3,
			},
			ConstPeriod: true,
			RandomRound: true, // Takes 1 or 2 rounds.
		})
	})

	t.Run("very delayed value exp", func(t *testing.T) {
		testQBFT(t, test{
			Instance: 3,
			ValueDelay: map[int64]time.Duration{
				1: time.Second * 5,
				2: time.Second * 10,
			},
			DecideRound: 4,
		})
	})

	t.Run("very delayed value const", func(t *testing.T) {
		testQBFT(t, test{
			Instance: 1,
			ValueDelay: map[int64]time.Duration{
				1: time.Second * 5,
				2: time.Second * 10,
			},
			ConstPeriod: true,
			RandomRound: true,
		})
	})

	t.Run("stagger delayed value exp", func(t *testing.T) {
		testQBFT(t, test{
			Instance: 0,
			ValueDelay: map[int64]time.Duration{
				1: time.Second * 0,
				2: time.Second * 1,
				3: time.Second * 2,
				4: time.Second * 3,
			},
			RandomRound: true, // Takes 1 or 2 rounds.
		})
	})

	t.Run("stagger delayed value const", func(t *testing.T) {
		testQBFT(t, test{
			Instance: 0,
			ValueDelay: map[int64]time.Duration{
				1: time.Second * 0,
				2: time.Second * 1,
				3: time.Second * 2,
				4: time.Second * 3,
			},
			ConstPeriod: true,
			RandomRound: true, // Takes 1 or 2 rounds.
		})
	})

	t.Run("round 1 leader no value, round 2 leader offline", func(t *testing.T) {
		testQBFT(t, test{
			Instance: 0,
			ValueDelay: map[int64]time.Duration{
				1: time.Second * 1,
			},
			StartDelay: map[int64]time.Duration{
				2: time.Second * 2,
			},
			ConstPeriod: true,
			DecideRound: 3,
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
				1: 0.1,
				2: 0.1,
				3: 0.1,
				4: 0.1,
			},
			ConstPeriod: true,
			RandomRound: true,
		})
	})

	t.Run("drop 30% const", func(t *testing.T) {
		testQBFT(t, test{
			Instance: 1,
			DropProb: map[int64]float64{
				1: 0.3,
				2: 0.3,
				3: 0.3,
				4: 0.3,
			},
			ConstPeriod: true,
			RandomRound: true,
		})
	})

	t.Run("fuzz", func(t *testing.T) {
		testQBFT(t, test{
			Instance:    1,
			Fuzz:        true,
			ConstPeriod: true,
			DecideRound: 1,
		})
	})

	t.Run("fuzz with late leader", func(t *testing.T) {
		testQBFT(t, test{
			Instance: 1,
			Fuzz:     true,
			StartDelay: map[int64]time.Duration{
				1: time.Second * 2,
				2: time.Second * 2,
			},
			ConstPeriod: true,
			RandomRound: true,
		})
	})

	t.Run("fuzz with very late leader", func(t *testing.T) {
		testQBFT(t, test{
			Instance: 1,
			Fuzz:     true,
			StartDelay: map[int64]time.Duration{
				1: time.Second * 10,
				2: time.Second * 10,
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
	ValueDelay    map[int64]time.Duration // Delays input value availability of certain processes
	DropProb      map[int64]float64       // DropProb [0..1] probability of dropped messages per processes
	BCastJitterMS int                     // Add random delays to broadcast of messages.
	CommitsAfter  int                     // Only broadcast commits after this round.
	DecideRound   int                     // Deterministic consensus at specific round
	PreparedVal   int                     // If prepared value decided, as opposed to leader's value.
	RandomRound   bool                    // Non-deterministic consensus at random round.
	Fuzz          bool                    // Enables fuzzing by Node 1.
}

func testQBFT(t *testing.T, test test) {
	t.Helper()

	const (
		n         = 4
		maxRound  = 50
		fifoLimit = 100
	)

	var (
		ctx, cancel = context.WithCancel(context.Background())
		clock       = new(fakeClock)
		receives    = make(map[int64]chan Msg[int64, int64, int64])
		broadcast   = make(chan Msg[int64, int64, int64])
		resultChan  = make(chan []Msg[int64, int64, int64], n)
		runChan     = make(chan error, n)
	)
	defer cancel()

	isLeader := makeIsLeader(n)
	defs := Definition[int64, int64, int64]{
		IsLeader: isLeader,
		NewTimer: func(round int64) (<-chan time.Time, func()) {
			d := time.Second
			if !test.ConstPeriod { // If not constant periods, then exponential.
				d = time.Duration(math.Pow(2, float64(round-1))) * time.Second
			}

			return clock.NewTimer(d)
		},
		Decide: func(_ context.Context, instance int64, value int64, round int64, qcommit []Msg[int64, int64, int64]) {
			resultChan <- qcommit
		},
		Compare: func(ctx context.Context, qcommit Msg[int64, int64, int64], inputValueSourceCh <-chan int64, inputValueSource int64, returnErr chan error, returnRes chan int64) {
			returnErr <- nil
		},
		LogRoundChange: func(ctx context.Context, instance int64, process, round, newRound int64, rule UponRule, msgs []Msg[int64, int64, int64]) {
			t.Logf("%s %v@%d change to %d ~= %v", clock.NowStr(), process, round, newRound, rule)
		},
		LogUponRule: func(_ context.Context, instance int64, process, round int64, msg Msg[int64, int64, int64], rule UponRule) {
			t.Logf("%s %d => %v@%d -> %v@%d ~= %v", clock.NowStr(), msg.Source(), msg.Type(), msg.Round(), process, round, rule)

			if round > maxRound {
				cancel()
			}
		},
		LogUnjust: func(_ context.Context, instance int64, process int64, msg Msg[int64, int64, int64]) {
			if test.Fuzz {
				return // Ignore unjust messages when fuzzing.
			}

			t.Logf("Unjust: %#v", msg)
			cancel()
		},
		Nodes:     n,
		FIFOLimit: fifoLimit,
	}

	for i := int64(1); i <= n; i++ {
		receive := make(chan Msg[int64, int64, int64], 1000)
		receives[i] = receive
		trans := Transport[int64, int64, int64]{
			Broadcast: func(ctx context.Context, typ MsgType, instance int64, source int64, round int64, value int64,
				pr int64, pv int64, justify []Msg[int64, int64, int64],
			) error {
				if round > maxRound {
					return errors.New("max round reach")
				}

				if typ == MsgCommit && int(round) <= test.CommitsAfter {
					t.Logf("%s %v dropping early commit for round %d", clock.NowStr(), source, round)
					return nil
				}

				t.Logf("%s %v => %v@%d", clock.NowStr(), source, typ, round)

				msg := newMsg(typ, instance, source, round, value, value, pr, pv, justify)
				receive <- msg // Always send to self first (no jitter, no drops).

				bcast(t, broadcast, msg, test.BCastJitterMS, clock)

				return nil
			},
			Receive: receive,
		}

		go func(i int64) {
			if d, ok := test.StartDelay[i]; ok {
				t.Logf("%s Node %d start delay %s", clock.NowStr(), i, d)
				ch, _ := clock.NewTimer(d)
				<-ch
				t.Logf("%s Node %d starting %s", clock.NowStr(), i, d)

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

			// Only enqueue input values for instances that:
			// - have a value delay
			// - or expect multiple rounds
			// - or otherwise only the leader of round 1.
			vChan := make(chan int64, 1)
			vsChan := make(chan int64, 1)

			if delay, ok := test.ValueDelay[i]; ok {
				go func() {
					ch, stop := clock.NewTimer(delay)
					defer stop()

					<-ch

					vChan <- i
				}()
			} else if test.DecideRound != 1 {
				go func() { vChan <- i }()
			} else if isLeader(test.Instance, 1, i) {
				go func() { vChan <- i }()
			}

			runChan <- Run(ctx, defs, trans, test.Instance, i, vChan, vsChan)
		}(i)
	}

	if test.Fuzz {
		go fuzz(ctx, clock, broadcast, test.Instance, 1)
	}

	var (
		results = make(map[int64]Msg[int64, int64, int64])
		count   int
		decided bool
		done    int
	)

	for {
		select {
		case msg := <-broadcast:
			for target, out := range receives {
				if target == msg.Source() {
					continue // Do not broadcast to self, we sent to self already.
				}

				if p, ok := test.DropProb[msg.Source()]; ok {
					if rand.Float64() < p {
						t.Logf("%s %v => %v@%d => %d (dropped)", clock.NowStr(), msg.Source(), msg.Type(), msg.Round(), target)
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
					require.Equal(t, previous.Value(), commit.Value(), "commit values")
				}

				if !test.RandomRound {
					require.EqualValues(t, test.DecideRound, commit.Round(), "wrong decide round")

					if test.PreparedVal != 0 { // Check prepared value if set
						require.EqualValues(t, test.PreparedVal, commit.Value(), "wrong prepared value")
					} else { // Otherwise check that leader value was used.
						require.True(t, isLeader(test.Instance, commit.Round(), commit.Value()), "not leader")
					}
				}

				results[commit.Source()] = commit
			}

			count++
			if count != n {
				continue
			}

			round := qCommit[0].Round()
			t.Logf("Got all results in round %d after %s: %#v", round, clock.SinceT0(), results)

			// Trigger shutdown
			decided = true

			cancel()
		case err := <-runChan:
			if !decided {
				require.Fail(t, "unexpected run error", err)
			}

			done++
			if done == n {
				return
			}
		default:
			time.Sleep(time.Microsecond)
			clock.Advance(time.Millisecond * 1)
		}
	}
}

// fuzz broadcasts random messages from the peer every 100ms (10/round).
func fuzz(ctx context.Context, clock *fakeClock, broadcast chan Msg[int64, int64, int64], instance, peerIdx int64) {
	for {
		timer, stop := clock.NewTimer(time.Millisecond * 100)
		select {
		case <-ctx.Done():
			return
		case <-timer:
			broadcast <- randomMsg(instance, peerIdx)
		}

		stop()
	}
}

func randomMsg(instance, peerIdx int64) msg {
	return msg{
		msgType:  1 + MsgType(rand.Intn(int(MsgDecided))),
		instance: instance,
		peerIdx:  peerIdx,
		round:    int64(rand.Intn(10)),
		value:    int64(rand.Intn(10)),
		pr:       int64(rand.Intn(10)),
		pv:       int64(rand.Intn(10)),
		justify:  nil,
	}
}

// bcast delays the message broadcast by between 1x and 2x jitterMS and drops messages.
func bcast(t *testing.T, broadcast chan Msg[int64, int64, int64], msg Msg[int64, int64, int64], jitterMS int, clock *fakeClock) {
	t.Helper()

	if jitterMS == 0 {
		broadcast <- msg
		return
	}

	go func() {
		deltaMS := int(float64(jitterMS) * rand.Float64())
		delay := time.Duration(jitterMS+deltaMS) * time.Millisecond
		t.Logf("%s %v => %v@%d (bcast delay %s)", clock.NowStr(), msg.Source(), msg.Type(), msg.Round(), delay)
		ch, _ := clock.NewTimer(delay)
		<-ch

		broadcast <- msg
	}()
}

// newMsg returns a new message to be broadcast.
func newMsg(typ MsgType, instance int64, source int64, round int64, value int64, valueSource int64,
	pr int64, pv int64, justify []Msg[int64, int64, int64],
) Msg[int64, int64, int64] {
	var msgs []msg

	for _, j := range justify {
		m := j.(msg)
		m.justify = nil // Clear nested justifications.
		msgs = append(msgs, m)
	}

	return msg{
		msgType:     typ,
		instance:    instance,
		peerIdx:     source,
		round:       round,
		value:       value,
		valueSource: valueSource,
		pr:          pr,
		pv:          pv,
		justify:     msgs,
	}
}

var _ Msg[int64, int64, int64] = msg{}

type msg struct {
	msgType     MsgType
	instance    int64
	peerIdx     int64
	round       int64
	value       int64
	valueSource int64
	pr          int64
	pv          int64
	justify     []msg
}

func (m msg) Type() MsgType {
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

func (m msg) Value() int64 {
	return m.value
}

func (m msg) ValueSource() (int64, error) {
	return m.valueSource, nil
}

func (m msg) PreparedRound() int64 {
	return m.pr
}

func (m msg) PreparedValue() int64 {
	return m.pv
}

func (m msg) Justification() []Msg[int64, int64, int64] {
	var resp []Msg[int64, int64, int64]
	for _, msg := range m.justify {
		resp = append(resp, msg)
	}

	return resp
}

// TestDecideScenarios verifies which value and round a node decides for
// adversarial and edge-case message sequences: conflicting COMMIT values and
// rounds, equivocating and spamming peers, crafted DECIDED messages, and
// post-decision noise. Deciding requires a full quorum of distinct sources
// committing to the exact same value in the exact same round, and a node
// decides at most once.
func TestDecideScenarios(t *testing.T) {
	const (
		n    = 4 // Quorum = 3.
		valA = 1
		valB = 2
		valC = 3
	)

	commitAt := func(source, round, value int64) msg {
		return msg{msgType: MsgCommit, peerIdx: source, round: round, value: value}
	}
	commit := func(source, value int64) msg {
		return commitAt(source, 1, value)
	}
	roundChange := func(source, round int64) msg {
		return msg{msgType: MsgRoundChange, peerIdx: source, round: round}
	}
	decidedMsg := func(source, round, value int64, justify []msg) msg {
		return msg{msgType: MsgDecided, peerIdx: source, round: round, value: value, justify: justify}
	}
	quorumCommits := func(value int64) []msg {
		return []msg{commit(1, value), commit(2, value), commit(3, value)}
	}
	// spamThenQuorum floods the FIFO buffer of peer 1 with junk commits before
	// peer 1's real commit completes the quorum.
	spamThenQuorum := func() []msg {
		msgs := []msg{commit(2, valB), commit(3, valB)}
		for range 120 { // FIFOLimit is 100.
			msgs = append(msgs, commit(1, valC))
		}

		return append(msgs, commit(1, valB))
	}

	tests := []struct {
		name         string
		msgs         []msg
		decided      int64 // Zero means no decision expected.
		decidedRound int64
		wantQcommit  int // Expected qcommit length, defaults to 3 (quorum).
	}{
		{
			name: "minority value arrives first",
			msgs: []msg{
				commit(1, valA),
				commit(2, valB),
				commit(3, valB),
				commit(0, valB),
			},
			decided:      valB,
			decidedRound: 1,
		},
		{
			name: "minority value arrives in the middle",
			msgs: []msg{
				commit(1, valB),
				commit(2, valA),
				commit(3, valB),
				commit(0, valB),
			},
			decided:      valB,
			decidedRound: 1,
		},
		{
			name: "two-two value split never decides",
			msgs: []msg{
				commit(0, valA),
				commit(1, valA),
				commit(2, valB),
				commit(3, valB),
			},
			decided: 0,
		},
		{
			name: "minority round arrives first",
			msgs: []msg{
				commitAt(1, 2, valB),
				commit(2, valB),
				commit(3, valB),
				commit(0, valB),
			},
			decided:      valB,
			decidedRound: 1,
		},
		{
			name: "two-two round split never decides",
			msgs: []msg{
				commit(0, valB),
				commit(1, valB),
				commitAt(2, 2, valB),
				commitAt(3, 2, valB),
			},
			decided: 0,
		},
		{
			name: "decides at future round after f+1 round changes",
			msgs: []msg{
				roundChange(1, 2),
				roundChange(2, 2),
				commitAt(1, 2, valB),
				commitAt(2, 2, valB),
				commitAt(3, 2, valB),
			},
			decided:      valB,
			decidedRound: 2,
		},
		{
			name: "equivocating peer's second vote counts toward quorum",
			msgs: []msg{
				commit(1, valA),
				commit(2, valB),
				commit(3, valB),
				commit(1, valB),
			},
			decided:      valB,
			decidedRound: 1,
		},
		{
			name: "equivocation alone cannot create quorum",
			msgs: []msg{
				commit(1, valA),
				commit(1, valB),
				commit(2, valA),
				commit(3, valB),
			},
			decided: 0,
		},
		{
			name: "duplicate commits do not inflate quorum",
			msgs: []msg{
				commit(1, valB),
				commit(1, valB),
				commit(1, valB),
				commit(2, valB),
			},
			decided: 0,
		},
		{
			name: "post-decide quorum for another value is ignored",
			msgs: []msg{
				commit(1, valB),
				commit(2, valB),
				commit(0, valB),
				commit(1, valC),
				commit(2, valC),
				commit(3, valC),
			},
			decided:      valB,
			decidedRound: 1,
		},
		{
			name: "justified decided message from a single relay peer",
			msgs: []msg{
				decidedMsg(3, 1, valB, quorumCommits(valB)),
			},
			decided:      valB,
			decidedRound: 1,
		},
		{
			name: "duplicate decided message decides only once",
			msgs: []msg{
				decidedMsg(3, 1, valB, quorumCommits(valB)),
				decidedMsg(2, 1, valB, quorumCommits(valB)),
			},
			decided:      valB,
			decidedRound: 1,
		},
		{
			name: "decided with insufficient justification is dropped",
			msgs: []msg{
				decidedMsg(3, 1, valB, []msg{commit(1, valB), commit(2, valB)}),
			},
			decided: 0,
		},
		{
			name: "decided with round-mismatched justification is dropped",
			msgs: []msg{
				// Justification commits are for round 1 while the decided message claims round 2.
				decidedMsg(3, 2, valB, quorumCommits(valB)),
			},
			decided: 0,
		},
		{
			name: "decided with value-mismatched justification is dropped",
			msgs: []msg{
				// Justification commits are for value A while the decided message claims value B.
				decidedMsg(3, 1, valB, quorumCommits(valA)),
			},
			decided: 0,
		},
		{
			name: "decided with rogue extra commit still decides the quorum value",
			msgs: []msg{
				decidedMsg(3, 1, valB, append([]msg{commit(3, valA)}, quorumCommits(valB)...)),
			},
			decided:      valB,
			decidedRound: 1,
			wantQcommit:  4, // Justification is forwarded verbatim, including the rogue commit.
		},
		{
			name: "stale-round decided accepted after node advanced",
			msgs: []msg{
				roundChange(1, 2),
				roundChange(2, 2),
				decidedMsg(3, 1, valB, quorumCommits(valB)),
			},
			decided:      valB,
			decidedRound: 1,
		},
		{
			name: "buffered future-round commits alone do not decide",
			// Quorum commits for round 2 arrive while still in round 1; the f+1 round
			// jump does not re-classify buffered messages. In production the node
			// recovers via the MsgDecided resend triggered by its ROUND-CHANGE broadcast.
			msgs: []msg{
				commitAt(1, 2, valB),
				commitAt(2, 2, valB),
				commitAt(3, 2, valB),
				roundChange(1, 2),
				roundChange(2, 2),
			},
			decided: 0,
		},
		{
			name: "re-sent commit after round jump decides from buffer",
			msgs: []msg{
				commitAt(1, 2, valB),
				commitAt(2, 2, valB),
				commitAt(3, 2, valB),
				roundChange(1, 2),
				roundChange(2, 2),
				commitAt(1, 2, valB),
			},
			decided:      valB,
			decidedRound: 2,
		},
		{
			name: "f+1 jump requires distinct sources",
			msgs: []msg{
				roundChange(1, 2),
				roundChange(1, 3),
				commitAt(1, 2, valB),
				commitAt(2, 2, valB),
				commitAt(3, 2, valB),
			},
			decided: 0,
		},
		{
			name:         "spam from one peer does not evict other peers' commits",
			msgs:         spamThenQuorum(),
			decided:      valB,
			decidedRound: 1,
		},
		{
			name: "commits with invalid round are ignored",
			msgs: []msg{
				commitAt(1, -1, valB),
				commitAt(2, -1, valB),
				commitAt(3, -1, valB),
			},
			decided: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			type decision struct {
				value   int64
				round   int64
				qcommit []Msg[int64, int64, int64]
			}

			recv := make(chan Msg[int64, int64, int64])
			decides := make(chan decision, 10)

			def := noopDef
			def.Nodes = n
			def.FIFOLimit = 100
			def.Decide = func(_ context.Context, _ int64, value int64, round int64, qcommit []Msg[int64, int64, int64]) {
				decides <- decision{value: value, round: round, qcommit: qcommit}
			}

			trans := Transport[int64, int64, int64]{
				Broadcast: func(context.Context, MsgType, int64, int64, int64, int64,
					int64, int64, []Msg[int64, int64, int64],
				) error {
					return nil
				},
				Receive: recv,
			}

			// Never-delivering input channels (this process is not a leader and proposes nothing).
			go func() {
				_ = Run(ctx, def, trans, 0, 0, make(chan int64), make(chan int64))
			}()

			send := func(m msg) {
				select {
				case recv <- m:
				case <-time.After(5 * time.Second):
					require.Fail(t, "timeout sending message to qbft instance")
				}
			}

			for _, m := range test.msgs {
				send(m)
			}

			// Inert flush: a commit for a far-future round is ignored, but its send only
			// completes once all messages above have been fully processed, making the
			// decide assertion below deterministic.
			send(commitAt(1, 99, valA))

			cancel()

			var got []decision

			drained := false
			for !drained {
				select {
				case d := <-decides:
					got = append(got, d)
				default:
					drained = true
				}
			}

			if test.decided == 0 {
				require.Empty(t, got, "expected no decision")
				return
			}

			require.Len(t, got, 1, "node must decide exactly once")

			d := got[0]
			require.Equal(t, test.decided, d.value, "decided unexpected value")
			require.Equal(t, test.decidedRound, d.round, "decided unexpected round")

			wantQcommit := test.wantQcommit
			if wantQcommit == 0 {
				wantQcommit = 3
			}

			require.Len(t, d.qcommit, wantQcommit)

			var matching int

			for _, q := range d.qcommit {
				if q.Type() == MsgCommit && q.Value() == d.value && q.Round() == d.round {
					matching++
				}
			}

			require.GreaterOrEqual(t, matching, 3,
				"qcommit must contain a quorum of commits matching the decided value and round")
		})
	}
}

// TestCompareFlowDecideScenarios verifies the interaction between the Compare flow
// (chain_split_halt feature) and the decide paths. Compare only gates the node's own
// PREPARE on a justified PRE-PREPARE: a Compare failure or timeout must suppress the
// PREPARE but never prevent deciding on a quorum of COMMITs or a justified DECIDED
// message.
func TestCompareFlowDecideScenarios(t *testing.T) {
	const (
		n      = 4
		leader = 1
		valB   = 2
	)

	type decision struct {
		value int64
		round int64
	}

	prePrepare := msg{msgType: MsgPrePrepare, peerIdx: leader, round: 1, value: valB}
	quorumCommits := []msg{
		{msgType: MsgCommit, peerIdx: 1, round: 1, value: valB},
		{msgType: MsgCommit, peerIdx: 2, round: 1, value: valB},
		{msgType: MsgCommit, peerIdx: 3, round: 1, value: valB},
	}
	decidedByRelay := msg{msgType: MsgDecided, peerIdx: 3, round: 1, value: valB, justify: quorumCommits}
	inertFlush := msg{msgType: MsgCommit, peerIdx: 1, round: 99, value: valB}

	// startNode runs a non-leader node with the given Compare behaviour and returns
	// a send function plus channels collecting broadcast types and decisions.
	startNode := func(t *testing.T, compareFn func(returnErr chan error),
		newTimer func(int64) (<-chan time.Time, func()),
	) (func(msg), chan MsgType, chan decision) {
		t.Helper()

		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		recv := make(chan Msg[int64, int64, int64])
		broadcasts := make(chan MsgType, 100)
		decides := make(chan decision, 10)

		def := noopDef
		def.Nodes = n
		def.FIFOLimit = 100
		def.IsLeader = func(_ int64, _ int64, process int64) bool { return process == leader }
		def.Compare = func(_ context.Context, _ Msg[int64, int64, int64], _ <-chan int64, _ int64, returnErr chan error, _ chan int64) {
			compareFn(returnErr)
		}
		def.Decide = func(_ context.Context, _ int64, value int64, round int64, _ []Msg[int64, int64, int64]) {
			decides <- decision{value: value, round: round}
		}

		if newTimer != nil {
			def.NewTimer = newTimer
		}

		trans := Transport[int64, int64, int64]{
			Broadcast: func(_ context.Context, typ MsgType, _ int64, _ int64, _ int64, _ int64,
				_ int64, _ int64, _ []Msg[int64, int64, int64],
			) error {
				broadcasts <- typ
				return nil
			},
			Receive: recv,
		}

		go func() {
			_ = Run(ctx, def, trans, 0, 0, make(chan int64), make(chan int64))
		}()

		send := func(m msg) {
			select {
			case recv <- m:
			case <-time.After(5 * time.Second):
				require.Fail(t, "timeout sending message to qbft instance")
			}
		}

		return send, broadcasts, decides
	}

	expectDecision := func(t *testing.T, decides chan decision) {
		t.Helper()

		select {
		case d := <-decides:
			require.Equal(t, decision{value: valB, round: 1}, d)
		case <-time.After(5 * time.Second):
			require.Fail(t, "timed out waiting for decision")
		}
	}

	requireNoPrepare := func(t *testing.T, broadcasts chan MsgType) {
		t.Helper()

		drained := false
		for !drained {
			select {
			case typ := <-broadcasts:
				require.NotEqual(t, MsgPrepare, typ, "node must not prepare a value that failed comparison")
			default:
				drained = true
			}
		}
	}

	failCompare := func(returnErr chan error) {
		returnErr <- errors.New("chain split detected")
	}

	t.Run("compare failure still decides on commit quorum", func(t *testing.T) {
		send, broadcasts, decides := startNode(t, failCompare, nil)

		send(prePrepare)

		for _, m := range quorumCommits {
			send(m)
		}

		send(inertFlush)

		expectDecision(t, decides)
		requireNoPrepare(t, broadcasts)
	})

	t.Run("compare failure still decides on justified decided", func(t *testing.T) {
		send, broadcasts, decides := startNode(t, failCompare, nil)

		send(prePrepare)
		send(decidedByRelay)
		send(inertFlush)

		expectDecision(t, decides)
		requireNoPrepare(t, broadcasts)
	})

	t.Run("compare success prepares leader value and decides", func(t *testing.T) {
		send, broadcasts, decides := startNode(t, func(returnErr chan error) {
			returnErr <- nil
		}, nil)

		send(prePrepare)

		select {
		case typ := <-broadcasts:
			require.Equal(t, MsgPrepare, typ, "node must prepare the leader value on compare success")
		case <-time.After(5 * time.Second):
			require.Fail(t, "timed out waiting for prepare broadcast")
		}

		for _, m := range quorumCommits {
			send(m)
		}

		send(inertFlush)

		expectDecision(t, decides)
	})

	t.Run("compare timeout changes round but decided still accepted", func(t *testing.T) {
		shortTimer := func(int64) (<-chan time.Time, func()) {
			timer := time.NewTimer(100 * time.Millisecond)
			return timer.C, func() { timer.Stop() }
		}

		// Compare never responds, so the round timer expires while waiting for it.
		send, broadcasts, decides := startNode(t, func(chan error) {}, shortTimer)

		send(prePrepare)

		// The compare timeout (or racing round timeout) must trigger a round change.
		deadline := time.After(5 * time.Second)

		roundChanged := false
		for !roundChanged {
			select {
			case typ := <-broadcasts:
				require.NotEqual(t, MsgPrepare, typ, "node must not prepare a value it could not compare")

				if typ == MsgRoundChange {
					roundChanged = true
				}
			case <-deadline:
				require.Fail(t, "timed out waiting for round change broadcast")
			}
		}

		send(decidedByRelay)

		expectDecision(t, decides)
		requireNoPrepare(t, broadcasts)
	})
}

// TestCommitOwnValueMinority verifies that a node decides the quorum value even when
// the minority value is its own: the node leads round 1, proposes, prepares and
// commits its own value A, but a quorum of peers commits value B. The node must
// decide B, and the qcommit justification must not contain its own A commit.
func TestCommitOwnValueMinority(t *testing.T) {
	const (
		n    = 4 // Quorum = 3.
		valA = 1
		valB = 2
	)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	type decision struct {
		value   int64
		round   int64
		qcommit []Msg[int64, int64, int64]
	}

	var (
		recv       = make(chan Msg[int64, int64, int64])
		echo       = make(chan msg, 100)
		ownCommits = make(chan int64, 10)
		decides    = make(chan decision, 1)
	)

	def := noopDef
	def.Nodes = n
	def.FIFOLimit = 100
	def.IsLeader = func(_ int64, round, process int64) bool { return round == 1 && process == 0 }
	def.Compare = func(_ context.Context, _ Msg[int64, int64, int64], _ <-chan int64, _ int64, returnErr chan error, _ chan int64) {
		returnErr <- nil
	}
	def.Decide = func(_ context.Context, _ int64, value int64, round int64, qcommit []Msg[int64, int64, int64]) {
		decides <- decision{value: value, round: round, qcommit: qcommit}
	}

	trans := Transport[int64, int64, int64]{
		Broadcast: func(_ context.Context, typ MsgType, _ int64, source int64, round int64,
			value int64, pr int64, pv int64, _ []Msg[int64, int64, int64],
		) error {
			if typ == MsgCommit {
				ownCommits <- value
			}

			// Echo own broadcasts back to self, as the real transport does.
			echo <- msg{msgType: typ, peerIdx: source, round: round, value: value, pr: pr, pv: pv}

			return nil
		},
		Receive: recv,
	}

	// Forward echoed own messages to the receive channel.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-echo:
				select {
				case <-ctx.Done():
					return
				case recv <- m:
				}
			}
		}
	}()

	// Provide our input value A, making the leader propose it at startup.
	inputCh := make(chan int64, 1)
	inputCh <- valA

	go func() {
		_ = Run(ctx, def, trans, 0, 0, inputCh, make(chan int64))
	}()

	send := func(m msg) {
		select {
		case recv <- m:
		case <-time.After(5 * time.Second):
			require.Fail(t, "timeout sending message to qbft instance")
		}
	}

	// Complete the prepare quorum for our own value A, so the node commits A.
	send(msg{msgType: MsgPrepare, peerIdx: 1, round: 1, value: valA})
	send(msg{msgType: MsgPrepare, peerIdx: 2, round: 1, value: valA})

	// Wait until the node has broadcast its own COMMIT for A.
	select {
	case v := <-ownCommits:
		require.EqualValues(t, valA, v, "node must commit its own proposed value")
	case <-time.After(5 * time.Second):
		require.Fail(t, "timed out waiting for own commit")
	}

	// A quorum of peers commits a different value B.
	send(msg{msgType: MsgCommit, peerIdx: 1, round: 1, value: valB})
	send(msg{msgType: MsgCommit, peerIdx: 2, round: 1, value: valB})
	send(msg{msgType: MsgCommit, peerIdx: 3, round: 1, value: valB})

	select {
	case d := <-decides:
		require.EqualValues(t, valB, d.value, "node must decide the quorum value, not its own")
		require.EqualValues(t, 1, d.round, "decided unexpected round")

		require.Len(t, d.qcommit, 3)

		for _, q := range d.qcommit {
			require.EqualValues(t, valB, q.Value(), "qcommit must not contain the node's own minority value")
			require.NotEqualValues(t, 0, q.Source(), "qcommit must not contain the node's own commit")
		}
	case <-time.After(5 * time.Second):
		require.Fail(t, "timed out waiting for decision")
	}
}

// TestDecidedRebroadcastLimits verifies that once consensus has decided, post-decision
// ROUND-CHANGE messages trigger at most one MsgDecided rebroadcast per source per
// (strictly increasing) round, capped at maxDecidedResends per source. This bounds
// amplification while still serving lagging peers that advance to new rounds.
func TestDecidedRebroadcastLimits(t *testing.T) {
	const (
		n       = 4
		process = 0
		value   = 42
	)

	// Build a justified MsgDecided: quorum (3) commits for round 1, value 42.
	commits := []msg{
		{msgType: MsgCommit, peerIdx: 1, round: 1, value: value},
		{msgType: MsgCommit, peerIdx: 2, round: 1, value: value},
		{msgType: MsgCommit, peerIdx: 3, round: 1, value: value},
	}
	decided := msg{msgType: MsgDecided, peerIdx: 1, round: 1, value: value, justify: commits}

	rc := func(source, round int64) msg {
		return msg{msgType: MsgRoundChange, peerIdx: source, round: round}
	}

	// runDecidedInstance starts a qbft instance, sends it the decided message and
	// returns a synchronous send function plus the channel collecting MsgDecided
	// broadcasts. The receive channel is unbuffered, so the instance only accepts
	// a send once it has fully processed all earlier messages (the just-sent
	// message may still be in flight, hence tests end with an inert flush send).
	// This makes broadcast-count assertions deterministic.
	runDecidedInstance := func(t *testing.T) (func(msg), chan MsgType) {
		t.Helper()

		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		recv := make(chan Msg[int64, int64, int64])
		decidedBroadcasts := make(chan MsgType, 100)

		def := noopDef
		def.Nodes = n
		def.FIFOLimit = 100
		def.Decide = func(context.Context, int64, int64, int64, []Msg[int64, int64, int64]) {}

		trans := Transport[int64, int64, int64]{
			Broadcast: func(_ context.Context, typ MsgType, _ int64, _ int64, _ int64, _ int64,
				_ int64, _ int64, _ []Msg[int64, int64, int64],
			) error {
				if typ == MsgDecided {
					decidedBroadcasts <- typ
				}

				return nil
			},
			Receive: recv,
		}

		// Never-delivering input channels (this process is not a leader and proposes nothing).
		go func() {
			_ = Run(ctx, def, trans, 0, process, make(chan int64), make(chan int64))
		}()

		send := func(m msg) {
			select {
			case recv <- m:
			case <-time.After(5 * time.Second):
				require.Fail(t, "timeout sending message to qbft instance")
			}
		}

		send(decided)

		return send, decidedBroadcasts
	}

	t.Run("dedup duplicates and stale rounds", func(t *testing.T) {
		send, broadcasts := runDecidedInstance(t)

		for _, m := range []msg{
			rc(2, 2), // Rebroadcast #1.
			rc(2, 2), // Duplicate, no rebroadcast.
			rc(2, 2), // Duplicate, no rebroadcast.
			rc(3, 2), // Rebroadcast #2 (other source).
			rc(3, 2), // Duplicate, no rebroadcast.
			rc(2, 1), // Stale round (already rebroadcast for round 2), no rebroadcast.
			rc(2, 3), // Rebroadcast #3 (source advanced to a new round).
		} {
			send(m)
		}

		// Flush with an inert message: once this send returns, all messages above
		// have been fully processed, so the broadcast count is final.
		send(rc(2, 1))

		require.Len(t, broadcasts, 3)
	})

	t.Run("resend cap per source", func(t *testing.T) {
		send, broadcasts := runDecidedInstance(t)

		// One peer keeps advancing rounds: only the first maxDecidedResends
		// ROUND-CHANGE messages may trigger a rebroadcast.
		for round := int64(2); round < 2+maxDecidedResends+5; round++ {
			send(rc(2, round))
		}

		// Flush with an inert message (stale round, never rebroadcast).
		send(rc(2, 1))

		require.Len(t, broadcasts, maxDecidedResends)
	})
}

func TestIsJustifiedPrePrepare(t *testing.T) {
	const (
		n        = 4
		instance = 1
	)

	// Preprepare with identical Pr but different Pvs.
	preprepare := msg{msgType: 1, instance: 1, peerIdx: 3, round: 6, value: 2, pr: 0, pv: 0, justify: []msg{
		{msgType: 4, instance: 1, peerIdx: 2, round: 6, value: 0, pr: 2, pv: 3},
		{msgType: 4, instance: 1, peerIdx: 3, round: 6, value: 0, pr: 2, pv: 3},
		{msgType: 4, instance: 1, peerIdx: 1, round: 6, value: 0, pr: 2, pv: 2},
		{msgType: 2, instance: 1, peerIdx: 3, round: 2, value: 2, pr: 0, pv: 0},
		{msgType: 2, instance: 1, peerIdx: 4, round: 2, value: 2, pr: 0, pv: 0},
		{msgType: 2, instance: 1, peerIdx: 1, round: 2, value: 2, pr: 0, pv: 0},
		{msgType: 2, instance: 1, peerIdx: 2, round: 2, value: 2, pr: 0, pv: 0},
	}}

	def := Definition[int64, int64, int64]{
		IsLeader: makeIsLeader(n),
		Nodes:    n,
	}

	ok := isJustifiedPrePrepare(def, instance, preprepare, 0)
	require.True(t, ok)
}

func TestFormulas(t *testing.T) {
	// assert given N asserts Q and F.
	assert := func(t *testing.T, n, q, f int) {
		t.Helper()

		d := Definition[any, int64, any]{Nodes: n}
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
	assert(t, 14, 10, 4)
	assert(t, 15, 10, 4)
	assert(t, 16, 11, 5)
	assert(t, 17, 12, 5)
	assert(t, 18, 12, 5)
	assert(t, 19, 13, 6)
	assert(t, 20, 14, 6)
	assert(t, 21, 14, 6)
	assert(t, 22, 15, 7)
}

// makeIsLeader returns a leader election function.
func makeIsLeader(n int64) func(int64, int64, int64) bool {
	return func(instance int64, round int64, process int64) bool {
		return (instance+round)%n == process
	}
}

// TestDuplicatePrePreparesRules tests that two pre-prepares for different rounds are not detected as duplicates.
func TestDuplicatePrePreparesRules(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const (
		noLeader = 1
		leader   = 2
	)

	newPreprepare := func(round int64) Msg[int64, int64, int64] {
		return msg{
			msgType: MsgPrePrepare,
			peerIdx: leader,
			round:   round,
			value:   42,
			// Justification not required since nodes and quorum both 0.
		}
	}

	def := noopDef
	def.IsLeader = func(_ int64, _ int64, process int64) bool {
		return process == leader
	}
	def.LogUponRule = func(ctx context.Context, instance int64, process, round int64, msg Msg[int64, int64, int64], uponRule UponRule) {
		log.Info(ctx, "UponRule", z.Str("rule", uponRule.String()), z.I64("round", msg.Round()))
		require.Equal(t, uponRule, UponJustifiedPrePrepare)

		if msg.Round() == 1 {
			return
		}

		if msg.Round() == 2 {
			cancel()
			return
		}

		require.Fail(t, "unexpected round", "round=%d", round)
	}
	def.Compare = func(ctx context.Context, qcommit Msg[int64, int64, int64], inputValueSourceCh <-chan int64, inputValueSource int64, returnErr chan error, returnValue chan int64) {
		returnErr <- nil
	}

	rChan := make(chan Msg[int64, int64, int64], 2)
	rChan <- newPreprepare(1)

	rChan <- newPreprepare(2)

	transport := noopTransport
	transport.Receive = rChan

	_ = Run(ctx, def, transport, 0, noLeader, InputValue(int64(1)), InputValueSource(int64(2)))
}

// noopTransport is a transport that does nothing.
var noopTransport = Transport[int64, int64, int64]{
	Broadcast: func(context.Context, MsgType, int64, int64, int64, int64, int64, int64, []Msg[int64, int64, int64]) error {
		return nil
	},
}

// TestEquivocatingLeaderDoublePrepare verifies that an honest node does NOT
// prepare two different values in the same round when an equivocating leader
// sends two justified PRE-PREPAREs with different values.
func TestEquivocatingLeaderDoublePrepare(t *testing.T) {
	const (
		n       = 4
		process = 0
		leader  = 1
	)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	recv := make(chan Msg[int64, int64, int64])
	prepares := make(chan int64, 100)

	def := noopDef
	def.Nodes = n
	def.FIFOLimit = 100
	def.IsLeader = func(_ int64, _ int64, p int64) bool { return p == leader }
	def.Compare = func(_ context.Context, _ Msg[int64, int64, int64], _ <-chan int64, _ int64, returnErr chan error, _ chan int64) {
		returnErr <- nil
	}
	def.Decide = func(context.Context, int64, int64, []Msg[int64, int64, int64]) {}

	trans := Transport[int64, int64, int64]{
		Broadcast: func(_ context.Context, typ MsgType, _ int64, _ int64, _ int64, value int64, _ int64, _ int64, _ []Msg[int64, int64, int64]) error {
			if typ == MsgPrepare {
				prepares <- value
			}

			return nil
		},
		Receive: recv,
	}

	go func() {
		_ = Run(ctx, def, trans, 0, process, make(chan int64), make(chan int64))
	}()

	send := func(m msg) {
		select {
		case recv <- m:
		case <-time.After(5 * time.Second):
			require.Fail(t, "timeout sending message to qbft instance")
		}
	}

	justify := []msg{
		{msgType: MsgRoundChange, peerIdx: 1, round: 2},
		{msgType: MsgRoundChange, peerIdx: 2, round: 2},
		{msgType: MsgRoundChange, peerIdx: 3, round: 2},
	}

	send(msg{msgType: MsgPrePrepare, peerIdx: leader, round: 2, value: 1, justify: justify})
	send(msg{msgType: MsgPrePrepare, peerIdx: leader, round: 2, value: 2, justify: justify})
	// Inert flush: stale round message ensures both above are processed.
	send(msg{msgType: MsgPrePrepare, peerIdx: leader, round: 1, value: 9})

	cancel()

	var prepared []int64

	for {
		select {
		case v := <-prepares:
			prepared = append(prepared, v)
		default:
			require.Equal(t, []int64{1}, prepared,
				"honest node must prepare at most one value per round")

			return
		}
	}
}

// TestZeroValuePrePrepareRejected verifies that a zero-value PRE-PREPARE from
// a Byzantine leader is rejected and does not cause the honest node to PREPARE.
func TestZeroValuePrePrepareRejected(t *testing.T) {
	const (
		n       = 4
		process = 0
		leader  = 1
	)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	recv := make(chan Msg[int64, int64, int64])
	prepares := make(chan int64, 100)

	def := noopDef
	def.Nodes = n
	def.FIFOLimit = 100
	def.IsLeader = func(_ int64, _ int64, p int64) bool { return p == leader }
	def.Compare = func(_ context.Context, _ Msg[int64, int64, int64], _ <-chan int64, _ int64, returnErr chan error, _ chan int64) {
		returnErr <- nil
	}
	def.Decide = func(context.Context, int64, int64, []Msg[int64, int64, int64]) {}

	trans := Transport[int64, int64, int64]{
		Broadcast: func(_ context.Context, typ MsgType, _ int64, _ int64, _ int64, value int64, _ int64, _ int64, _ []Msg[int64, int64, int64]) error {
			if typ == MsgPrepare {
				prepares <- value
			}

			return nil
		},
		Receive: recv,
	}

	go func() {
		_ = Run(ctx, def, trans, 0, process, make(chan int64), make(chan int64))
	}()

	send := func(m msg) {
		select {
		case recv <- m:
		case <-time.After(5 * time.Second):
			require.Fail(t, "timeout sending message to qbft instance")
		}
	}

	// Round-1 PRE-PREPARE with zero value (int64 zero == 0).
	send(msg{msgType: MsgPrePrepare, peerIdx: leader, round: 1, value: 0})
	// Inert flush.
	send(msg{msgType: MsgPrePrepare, peerIdx: leader, round: 1, value: 0})

	// Stop the QBFT goroutine before draining, so no late writes race with the read.
	cancel()

	select {
	case v := <-prepares:
		require.Failf(t, "honest node must reject zero-value PRE-PREPARE", "got PREPARE with value %d", v)
	default:
	}
}

// noopDef is a definition that does nothing.
var noopDef = Definition[int64, int64, int64]{
	IsLeader:       func(int64, int64, int64) bool { return false },
	NewTimer:       func(int64) (<-chan time.Time, func()) { return nil, func() {} },
	LogUponRule:    func(context.Context, int64, int64, int64, Msg[int64, int64, int64], UponRule) {},
	LogRoundChange: func(context.Context, int64, int64, int64, int64, UponRule, []Msg[int64, int64, int64]) {},
	LogUnjust:      func(context.Context, int64, int64, Msg[int64, int64, int64]) {},
}

type testChainSplit struct {
	ValueSource map[int64]int64 // Use different value source for certain processes (used for chain-split-halt feature).
	DecideRound int             // Deterministic consensus at specific round.
	PreparedVal int             // If prepared value decided, as opposed to leader's value.
	ShouldHalt  bool            // If halt is expected (no consensus reachead).
}

var errChainSplitHalt = errors.New("chain split halt")

// TestCompareRetainsValueOnError verifies that the compare flow does not lose the
// local value read by the comparator when the comparison also fails. The comparator
// sends the value and the error back-to-back on buffered channels, so both select
// cases can be ready simultaneously and the select picks one at random; the read
// value must be returned regardless of which case wins, otherwise subsequent rounds
// block forever on the already-consumed input value source channel.
func TestCompareRetainsValueOnError(t *testing.T) {
	const localValue = 42

	// Repeat since the select picks randomly among the two ready cases.
	for range 1000 {
		// Model the racy state directly: the comparator already completed both
		// sends before the await loop polled the select.
		compareErr := make(chan error, 1)

		compareValue := make(chan int64, 1)
		compareValue <- localValue

		compareErr <- errors.New("mismatch")

		vs, err := awaitCompare(context.Background(), compareErr, compareValue, nil, 0)
		require.ErrorIs(t, err, errCompare)
		require.EqualValues(t, localValue, vs, "local value must not be lost when comparison fails")
	}
}

func TestChainSplit(t *testing.T) {
	t.Run("same value", func(t *testing.T) {
		testQBFTChainSplit(t, testChainSplit{
			DecideRound: 1,
			ValueSource: map[int64]int64{
				1: 1,
				2: 1,
				3: 1,
				4: 1,
			},
			PreparedVal: 1,
		})
	})

	t.Run("non-leader peer has different value", func(t *testing.T) {
		testQBFTChainSplit(t, testChainSplit{
			DecideRound: 1,
			ValueSource: map[int64]int64{
				1: 1,
				2: 3,
				3: 1,
				4: 1,
			},
			PreparedVal: 1,
		})
	})

	t.Run("first leader has different value, second leader succeeds", func(t *testing.T) {
		testQBFTChainSplit(t, testChainSplit{
			DecideRound: 2,
			ValueSource: map[int64]int64{
				1: 3,
				2: 1,
				3: 1,
				4: 1,
			},
			PreparedVal: 1,
		})
	})

	t.Run("no consensus - halt", func(t *testing.T) {
		testQBFTChainSplit(t, testChainSplit{
			ValueSource: map[int64]int64{
				1: 1,
				2: 1,
				3: 3,
				4: 3,
			},
			ShouldHalt: true,
		})
	})
}

func testQBFTChainSplit(t *testing.T, test testChainSplit) {
	t.Helper()

	const (
		n         = 4
		maxRound  = 10
		fifoLimit = 100
	)

	var (
		ctx, cancel            = context.WithCancel(context.Background())
		clock                  = new(fakeClock)
		receiveChannelsPerNode = make(map[int64]chan Msg[int64, int64, int64])
		broadcast              = make(chan Msg[int64, int64, int64])
		resultChan             = make(chan []Msg[int64, int64, int64], n)
		runChan                = make(chan error, n)
		instance               = int64(0)
	)
	defer cancel()

	isLeader := makeIsLeader(n)
	defs := Definition[int64, int64, int64]{
		IsLeader: isLeader,
		NewTimer: func(round int64) (<-chan time.Time, func()) {
			return clock.NewTimer(time.Duration(math.Pow(2, float64(round-1))) * time.Second)
		},
		Decide: func(_ context.Context, instance int64, value int64, round int64, qcommit []Msg[int64, int64, int64]) {
			resultChan <- qcommit
		},
		Compare: func(ctx context.Context, qcommit Msg[int64, int64, int64], inputValueSourceCh <-chan int64, inputValueSource int64, returnCh chan error, returnIVS chan int64) {
			vs, _ := qcommit.ValueSource()

			if inputValueSource == 0 {
				inputValueSource = <-inputValueSourceCh
				returnIVS <- inputValueSource
			}

			if vs != inputValueSource {
				returnCh <- errors.New("mismatch", z.I64("leadervalue", vs), z.I64("localvalue", inputValueSource))
				return
			}

			returnCh <- nil
		},
		LogRoundChange: func(ctx context.Context, instance int64, process, round, newRound int64, rule UponRule, msgs []Msg[int64, int64, int64]) {
			t.Logf("%s %v@%d change to %d ~= %v", clock.NowStr(), process, round, newRound, rule)
		},
		LogUponRule: func(_ context.Context, instance int64, process, round int64, msg Msg[int64, int64, int64], rule UponRule) {
			t.Logf("%s %d => %v@%d -> %v@%d ~= %v", clock.NowStr(), msg.Source(), msg.Type(), msg.Round(), process, round, rule)

			if round > maxRound {
				cancel()
			}
		},
		LogUnjust: func(_ context.Context, instance int64, process int64, msg Msg[int64, int64, int64]) {
			t.Logf("Unjust: %#v", msg)
		},
		Nodes:     n,
		FIFOLimit: fifoLimit,
	}

	// Start each charon node
	for i := int64(1); i <= n; i++ {
		receive := make(chan Msg[int64, int64, int64], 1000)
		receiveChannelsPerNode[i] = receive
		transport := Transport[int64, int64, int64]{
			Broadcast: func(ctx context.Context, typ MsgType, instance int64, source int64, round int64, value int64,
				pr int64, pv int64, justify []Msg[int64, int64, int64],
			) error {
				if round > maxRound {
					if test.ShouldHalt {
						return errChainSplitHalt
					}

					return errors.New("max round reach")
				}

				t.Logf("%s %v => %v@%d", clock.NowStr(), source, typ, round)

				msg := newMsg(typ, instance, source, round, value, value, pr, pv, justify)
				receive <- msg // Always send to self first (no jitter, no drops).

				bcast(t, broadcast, msg, 0, clock)

				return nil
			},
			Receive: receive,
		}

		// Enqueue input values synchronously (channels are buffered), so nodes
		// never wait on a feeder goroutine while virtual time advances.
		vChan := make(chan int64, 1)
		vsChan := make(chan int64, 1)

		vChan <- test.ValueSource[i]

		vsChan <- test.ValueSource[i]

		go func(i int64) {
			runChan <- Run(ctx, defs, transport, instance, i, vChan, vsChan)
		}(i)
	}

	var (
		results = make(map[int64]Msg[int64, int64, int64])
		count   int
		decided bool
		done    int
	)

	for {
		select {
		case msg := <-broadcast:
			for target, out := range receiveChannelsPerNode {
				if target == msg.Source() {
					continue // Do not broadcast to self, we sent to self already.
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
					require.Equal(t, previous.Value(), commit.Value(), "commit values")
				}

				require.EqualValues(t, test.DecideRound, commit.Round(), "wrong decide round")

				if test.PreparedVal != 0 { // Check prepared value if set
					require.EqualValues(t, test.PreparedVal, commit.Value(), "wrong prepared value")
				}

				results[commit.Source()] = commit
			}

			count++
			if count != n {
				continue
			}

			round := qCommit[0].Round()
			t.Logf("Got all results in round %d after %s: %#v", round, clock.SinceT0(), results)

			// Trigger shutdown
			decided = true

			cancel()
		case err := <-runChan:
			if !decided && !errors.Is(err, errChainSplitHalt) {
				require.Fail(t, "unexpected run error", err)
			}

			done++
			if done == n {
				return
			}
		default:
			// Only advance virtual time when the system is quiescent: every node
			// still deciding is parked on its round timer, and no messages remain
			// queued in the receive buffers. Otherwise real-world goroutine
			// scheduling lag skews nodes multiple virtual seconds apart, pushing
			// consensus to a later round than the scenario expects.
			quiescent := clock.NumActive() >= n-done-count

			for _, out := range receiveChannelsPerNode {
				if len(out) > 0 {
					quiescent = false
					break
				}
			}

			time.Sleep(time.Microsecond)

			if !quiescent {
				continue
			}

			clock.Advance(time.Millisecond * 1)
		}
	}
}
