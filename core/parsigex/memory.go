// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package parsigex

import (
	"context"
	"sync"

	"github.com/obolnetwork/charon/core"
)

type sub func(context.Context, core.Duty, core.ParSignedDataSet) error

// NewMemExFunc returns a function that itself returns in-memory exchange components
// that exchange partial signatures.
func NewMemExFunc() func() MemEx {
	var (
		mu    sync.Mutex
		index int
		subs  = make(map[int][]sub)
	)

	return func() MemEx {
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
