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
	"fmt"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core/qbft"
)

func TestQBFT(t *testing.T) {
	t.Run("happy 0", func(t *testing.T) {
		testQBFT(t, test{
			Instance:   0,
			StartDelay: nil,
			Result:     1,
		})
	})

	t.Run("happy 1", func(t *testing.T) {
		testQBFT(t, test{
			Instance:   1,
			StartDelay: nil,
			Result:     2,
		})
	})

	t.Run("leader late exp", func(t *testing.T) {
		testQBFT(t, test{
			Instance:   0,
			StartDelay: map[int64]time.Duration{1: time.Second * 2},
			Result:     2,
		})
	})

	t.Run("leader late const", func(t *testing.T) {
		testQBFT(t, test{
			Instance:    0,
			StartDelay:  map[int64]time.Duration{1: time.Second * 2},
			ConstPeriod: true,
			Result:      2,
		})
	})

	t.Run("very late exp", func(t *testing.T) {
		testQBFT(t, test{
			Instance: 3,
			StartDelay: map[int64]time.Duration{
				1: time.Second * 5,
				2: time.Second * 10,
			},
			Result: 3,
		})
	})

	t.Run("very late const", func(t *testing.T) {
		testQBFT(t, test{
			Instance: 1,
			StartDelay: map[int64]time.Duration{
				1: time.Second * 5,
				2: time.Second * 10,
			},
			ConstPeriod:  true,
			ResultRandom: true,
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
			ResultRandom: true, // Takes 1 or 2 rounds.
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
			ConstPeriod:  true,
			ResultRandom: true, // Takes 1 or 2 rounds.
		})
	})

	t.Run("500ms jitter exp", func(t *testing.T) {
		testQBFT(t, test{
			Instance:      3,
			BCastJitterMS: 500,
			ResultRandom:  true,
		})
	})

	t.Run("200ms jitter const", func(t *testing.T) {
		testQBFT(t, test{
			Instance:      3,
			BCastJitterMS: 200, // 0.2-0.4s network delay * 3msgs/round == 0.6-1.2s delay per 1s round.
			ConstPeriod:   true,
			ResultRandom:  true,
		})
	})
}

type test struct {
	Instance      int64                   // Consensus instance, only affects leader election.
	ConstPeriod   bool                    // ConstPeriod results in 1s round timeout, otherwise exponential (1s,2s,4s...)
	StartDelay    map[int64]time.Duration // Delays start of certain processes
	BCastJitterMS int                     // Add random delays to broadcast of messages.
	Result        int                     // Deterministic consensus result
	ResultRandom  bool                    // Non-deterministic consensus result
}

func testQBFT(t *testing.T, test test) {
	t.Helper()

	const (
		n = 4
		q = 3
		f = 1
	)

	var (
		ctx, cancel = context.WithCancel(context.Background())
		clock       = new(fakeClock)
		receives    []chan qbft.Msg
		broadcast   = make(chan qbft.Msg)
		resultChan  = make(chan string, n)
		errChan     = make(chan error, n)
	)
	defer cancel()

	defs := qbft.Definition{
		IsLeader: func(instance []byte, round int64, process int64) bool {
			i, err := strconv.ParseInt(string(instance), 10, 64)
			require.NoError(t, err)

			return (i+round)%n == process
		},
		NewTimer: func(round int64) (<-chan time.Time, func()) {
			d := time.Second
			if !test.ConstPeriod { // If not constant periods, then exponential.
				d = time.Duration(math.Pow(2, float64(round-1))) * time.Second
			}

			return clock.NewTimer(d)
		},
		Decide: func(instance []byte, value []byte, qcommit []qbft.Msg) {
			resultChan <- string(value)
		},
		LogUponRule: func(instance []byte, process, round int64, msg qbft.Msg, rule string) {
			t.Logf("%s %d => %v@%d -> %v@%d ~= %v", clock.NowStr(), msg.Source, msg.Type, msg.Round, process, round, rule)
			if round > 50 {
				cancel()
			} else if strings.Contains(rule, "Unjust") {
				t.Logf("Unjustified PRE-PREPARE: %#v", msg)
				cancel()
			}
		},
		Quorum: q,
		Faulty: f,
	}

	for i := int64(0); i < n; i++ {
		receive := make(chan qbft.Msg, 1000)
		receives = append(receives, receive)
		trans := qbft.Transport{
			Broadcast: func(msg qbft.Msg) {
				bcastJitter(broadcast, msg, test.BCastJitterMS, clock)
			},
			SendQCommit: func(_ int64, qCommit []qbft.Msg) {
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

			instance := strconv.FormatInt(test.Instance, 10)
			err := qbft.Run(ctx, defs, trans, []byte(instance), i, []byte(fmt.Sprint(i)))
			if err != nil {
				errChan <- err
				return
			}
		}(i)
	}

	var results []string

	for {
		select {
		case msg := <-broadcast:
			t.Logf("%s %v => %v@%d", clock.NowStr(), msg.Source, msg.Type, msg.Round)
			for _, out := range receives {
				out <- msg
				if rand.Float64() < 0.1 { // Send 10% messages twice
					out <- msg
				}
			}
		case result := <-resultChan:
			if test.ResultRandom {
				// Ensure that all results are the same at least
				for _, previous := range results {
					require.Equal(t, previous, result)
				}
			} else {
				require.Equal(t, fmt.Sprint(test.Result), result)
			}

			results = append(results, result)
			if len(results) == n {
				t.Logf("Got all results after %v: %v", clock.SinceT0(), results)
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

// bcastJitter delays the message broadcast by between 1x and 2x jitterMS.
func bcastJitter(broadcast chan qbft.Msg, msg qbft.Msg, jitterMS int, clock *fakeClock) {
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
