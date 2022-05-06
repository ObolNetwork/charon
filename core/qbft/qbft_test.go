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
	"math/rand"
	"runtime"
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

	t.Run("leader late", func(t *testing.T) {
		testQBFT(t, test{
			Instance:   0,
			StartDelay: map[int64]time.Duration{1: time.Second * 2},
			Result:     2,
		})
	})

	t.Run("very late", func(t *testing.T) {
		testQBFT(t, test{
			Instance: 0,
			StartDelay: map[int64]time.Duration{
				1: time.Second * 5,
				2: time.Second * 10,
			},
			Result: 3,
		})
	})

	t.Run("stagger start", func(t *testing.T) {
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

	t.Run("500ms jitter", func(t *testing.T) {
		testQBFT(t, test{
			Instance:      3,
			BCastJitterMS: 500,
			ResultRandom:  true,
		})
	})
}

type test struct {
	Instance      int64
	StartDelay    map[int64]time.Duration
	BCastJitterMS int
	Result        int
	ResultRandom  bool
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
		IsLeader: func(instance, round int64, process int64) bool {
			return (instance+round)%n == process
		},
		NewTimer: func(round int64) (<-chan time.Time, func()) {
			return clock.NewTimer(time.Duration(round*round) * time.Second)
		},
		IsValid: func(instance int64, msg qbft.Msg) bool {
			return true
		},
		LogUponRule: func(instance, process, round int64, msg qbft.Msg, rule string) {
			t.Logf("%d -> %v@%d -> %v@%d ~= %v", msg.Source, msg.Type, msg.Round, process, round, rule)
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
			Receive: receive,
		}

		go func(i int64) {
			if d, ok := test.StartDelay[i]; ok {
				ch, _ := clock.NewTimer(d)
				<-ch
			}

			result, err := qbft.Run(ctx, defs, trans, test.Instance, i, []byte(fmt.Sprint(i)))
			if err != nil {
				errChan <- err
				return
			}
			resultChan <- string(result)
		}(i)
	}

	var results []string

	for {
		runtime.Gosched()

		select {
		case msg := <-broadcast:
			t.Logf("%v -> %v@%d", msg.Source, msg.Type, msg.Round)
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
