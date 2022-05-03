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
	for i := 0; i < nodes; i++ {
		i := i // Copy loop variable.
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
	round1Shares map[msgKey]sharing.ShamirShare

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
		t.round1Shares = make(map[msgKey]sharing.ShamirShare)
	}

	// Duplicate broadcast messages.
	for i := 1; i <= t.nodes; i++ {
		for key, round1Bcast := range bcast {
			t.round1Bcast[msgKey{
				ValIdx:   key.ValIdx,
				SourceID: key.SourceID,
				TargetID: uint32(i),
			}] = round1Bcast
		}
	}
	// Pool p2p messages.
	for key, share := range shares {
		t.round1Shares[key] = share
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
			return t.round1Bcast, t.round1Shares, nil
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
				TargetID: uint32(i),
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
