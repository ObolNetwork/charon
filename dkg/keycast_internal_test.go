// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	"github.com/obolnetwork/charon/testutil"
)

func TestKeyCastNoNetwork(t *testing.T) {
	random := rand.New(rand.NewSource(0))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const (
		nodes = 3
		vals  = 2
		seed  = 1
	)

	var ops []cluster.Operator
	for i := 0; i < nodes; i++ {
		_, r := testutil.RandomENR(t, seed)

		ops = append(ops, cluster.Operator{
			ENR: r.String(),
		})
	}

	var feeRecipientAddrs, withdrawalAddrs []string
	for i := 0; i < vals; i++ {
		feeRecipientAddrs = append(feeRecipientAddrs, testutil.RandomETHAddress())
		withdrawalAddrs = append(withdrawalAddrs, testutil.RandomETHAddress())
	}

	def, err := cluster.NewDefinition("test def", vals, nodes, feeRecipientAddrs, withdrawalAddrs, "", cluster.Creator{}, ops, random)
	require.NoError(t, err)

	tp := new(memTransport)

	var eg errgroup.Group
	for i := 0; i < nodes; i++ {
		i := i // Copy loop variable.
		eg.Go(func() error {
			shares, err := runKeyCast(ctx, def, tp, i)
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
