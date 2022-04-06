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
func NewMemExFunc() func() core.ParSigEx {
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
