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

package dkg

import (
	"context"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestKeyCastNoNetwork(t *testing.T) {
	random := rand.New(rand.NewSource(0))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const (
		nodes = 3
		vals  = 2
	)

	var ops []cluster.Operator
	for i := 0; i < nodes; i++ {
		_, r := testutil.RandomENR(t, random)
		enrStr, err := p2p.EncodeENR(r)
		require.NoError(t, err)

		ops = append(ops, cluster.Operator{
			ENR: enrStr,
		})
	}

	def, err := cluster.NewDefinition("test def", vals, nodes, "", "", "", cluster.Creator{}, ops, random)
	require.NoError(t, err)

	tp := new(memTransport)

	var eg errgroup.Group
	for i := 0; i < nodes; i++ {
		i := i // Copy loop variable.
		eg.Go(func() error {
			shares, err := runKeyCast(ctx, def, tp, i, random)
			if err != nil {
				cancel()
				return err
			}
			require.Len(t, shares, vals)

			return nil
		})
	}

	require.NoError(t, eg.Wait())
}

// memTransport is a very simple in-memory kcTransport for testing.
// The dealers servFunc is called directly by participants.
type memTransport struct {
	mu       sync.Mutex
	servFunc func(nodeIdx int) (msg []byte, err error)
}

func (m *memTransport) ServeShares(ctx context.Context, f func(nodeIdx int) (msg []byte, err error)) {
	m.mu.Lock()
	m.servFunc = f
	m.mu.Unlock()

	<-ctx.Done()

	m.mu.Lock()
	m.servFunc = nil
	m.mu.Unlock()
}

func (m *memTransport) GetShares(ctx context.Context, nodeIdx int) ([]byte, error) {
	// Wait for servFunc to be populated.
	for ctx.Err() == nil {
		m.mu.Lock()
		if m.servFunc != nil {
			resp, err := m.servFunc(nodeIdx)
			m.mu.Unlock()

			return resp, err
		}
		m.mu.Unlock()
		time.Sleep(time.Millisecond)
	}

	return nil, ctx.Err()
}
