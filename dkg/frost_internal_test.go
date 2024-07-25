// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/coinbase/kryptology/pkg/dkg/frost"
	"github.com/coinbase/kryptology/pkg/sharing"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestFrostDKG(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const (
		nodes = 3
		vals  = 2
	)

	tp := &frostMemTransport{nodes: nodes}

	var eg errgroup.Group
	for i := range nodes {
		eg.Go(func() error {
			shares, err := runFrostParallel(ctx, tp, vals, nodes, nodes, uint32(i+1), "test context")
			if err != nil {
				cancel()
				return err
			}
			require.Len(t, shares, vals)
			// TODO(corver): verify shares.
			return nil
		})
	}

	require.NoError(t, eg.Wait())
}

type frostMemTransport struct {
	mu    sync.Mutex
	nodes int

	round1       int
	round1Bcast  map[msgKey]frost.Round1Bcast
	round1Shares map[uint32]map[msgKey]sharing.ShamirShare

	round2      int
	round2Bcast map[msgKey]frost.Round2Bcast
}

func (t *frostMemTransport) Round1(ctx context.Context, bcast map[msgKey]frost.Round1Bcast, shares map[msgKey]sharing.ShamirShare,
) (
	map[msgKey]frost.Round1Bcast, map[msgKey]sharing.ShamirShare, error,
) {
	t.mu.Lock()

	if t.round1 == 0 {
		t.round1Bcast = make(map[msgKey]frost.Round1Bcast)
		t.round1Shares = make(map[uint32]map[msgKey]sharing.ShamirShare)
	}

	var sourceID uint32
	// Duplicate broadcast messages.
	for i := 1; i <= t.nodes; i++ {
		for key, round1Bcast := range bcast {
			sourceID = key.SourceID

			t.round1Bcast[msgKey{
				ValIdx:   key.ValIdx,
				SourceID: key.SourceID,
				TargetID: 0,
			}] = round1Bcast
		}
	}
	// Pool p2p messages.
	for key, share := range shares {
		shares, ok := t.round1Shares[key.TargetID]
		if !ok {
			shares = make(map[msgKey]sharing.ShamirShare)
		}
		shares[key] = share
		t.round1Shares[key.TargetID] = shares
	}

	t.round1++
	t.mu.Unlock()

	// Wait for all round1 calls to come in, then return shared result.
	for {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		t.mu.Lock()
		if t.round1 == t.nodes {
			t.mu.Unlock()
			return t.round1Bcast, t.round1Shares[sourceID], nil
		}
		t.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
}

func (t *frostMemTransport) Round2(ctx context.Context, bcast map[msgKey]frost.Round2Bcast) (map[msgKey]frost.Round2Bcast, error) {
	t.mu.Lock()

	if t.round2 == 0 {
		t.round2Bcast = make(map[msgKey]frost.Round2Bcast)
	}

	// Duplicate broadcast messages.
	for i := 1; i <= t.nodes; i++ {
		for key, round2Bcast := range bcast {
			t.round2Bcast[msgKey{
				ValIdx:   key.ValIdx,
				SourceID: key.SourceID,
				TargetID: 0,
			}] = round2Bcast
		}
	}

	t.round2++
	t.mu.Unlock()

	// Wait for all round2 calls to come in, then return shared result.
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		t.mu.Lock()
		if t.round2 == t.nodes {
			t.mu.Unlock()
			return t.round2Bcast, nil
		}
		t.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
}
