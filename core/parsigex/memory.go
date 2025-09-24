// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package parsigex

import (
	"context"
	"sync"
	"time"

	"github.com/obolnetwork/charon/core"
)

type sub func(context.Context, core.Duty, core.ParSignedDataSet) error

// NewMemExFunc returns a function that itself returns in-memory exchange components
// that exchange partial signatures.
func NewMemExFunc(expectedPeers int) func() core.ParSigEx {
	var (
		mu    sync.Mutex
		index int
		subs  = make(map[int][]sub)
	)

	return func() core.ParSigEx {
		mu.Lock()
		defer mu.Unlock()

		i := index
		index++

		return MemEx{
			addSub: func(s sub) {
				mu.Lock()
				defer mu.Unlock()

				subs[i] = append(subs[i], s)
			},

			getSubs: func() []sub {
				// Wait for all expected peers to be registered.
				t0 := time.Now()

				for {
					mu.Lock()

					if len(subs) == expectedPeers {
						mu.Unlock()
						break
					}

					mu.Unlock()

					if time.Since(t0) > 10*time.Second {
						panic("timeout waiting for all peers to register")
					}

					time.Sleep(time.Millisecond)
				}

				mu.Lock()
				defer mu.Unlock()

				var others []sub // Get other peer's subscriptions.

				for index, s := range subs {
					if index == i {
						continue
					}

					others = append(others, s...)
				}

				return others
			},
		}
	}
}

// MemEx provides an in-memory implementation of
// the core workflow's partial signature exchange component.
type MemEx struct {
	addSub  func(sub)
	getSubs func() []sub
}

// Broadcast broadcasts the partially signed duty data set to all peers.
func (s MemEx) Broadcast(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
	for _, sub := range s.getSubs() {
		err := sub(ctx, duty, set)
		if err != nil {
			return err
		}
	}

	return nil
}

// Subscribe registers a callback when a partially signed duty set
// is received from a peer.
func (s MemEx) Subscribe(fn func(context.Context, core.Duty, core.ParSignedDataSet) error) {
	s.addSub(fn)
}
