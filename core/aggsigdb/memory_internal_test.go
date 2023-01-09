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

package aggsigdb

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

func TestDutyExpiration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	deadliner := newTestDeadliner()
	db := NewMemDB(deadliner)

	go db.Run(ctx)

	slot := int64(99)
	duty := core.NewAttesterDuty(slot)
	pubkey := testutil.RandomCorePubKey(t)
	sig := testutil.RandomCoreSignature()

	err := db.Store(ctx, duty, pubkey, sig)
	require.NoError(t, err)

	resp, err := db.Await(ctx, duty, pubkey)
	require.NoError(t, err)
	require.Equal(t, sig, resp)

	deadliner.Expire()

	require.Empty(t, db.data)
	require.Empty(t, db.keysByDuty)
}

func TestCancelledQuery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db := NewMemDB(newTestDeadliner())

	queryCount := make(chan int, 1)
	db.queryCallback = func(queries []readQuery) {
		queryCount <- len(queries)
	}

	go db.Run(ctx)

	slot := int64(99)
	duty := core.NewAttesterDuty(slot)
	pubkey := testutil.RandomCorePubKey(t)
	sig := testutil.RandomCoreSignature()

	// Enqueue 2 queries and wait for them to be blocked.
	qctx, qcancel := context.WithCancel(ctx)

	go func() {
		_, err := db.Await(qctx, duty, pubkey)
		require.ErrorIs(t, err, context.Canceled)
	}()
	require.Equal(t, 1, <-queryCount)

	go func() {
		_, err := db.Await(qctx, duty, pubkey)
		require.ErrorIs(t, err, context.Canceled)
	}()
	require.Equal(t, 2, <-queryCount)

	// Cancel queries
	qcancel()

	// Store something and ensure no blocked queries
	err := db.Store(ctx, duty, pubkey, sig)
	require.NoError(t, err)
	require.Equal(t, 0, <-queryCount)
}

func newTestDeadliner() *testDeadliner {
	return &testDeadliner{
		ch: make(chan core.Duty),
	}
}

// testDeadliner is a mock deadliner implementation.
type testDeadliner struct {
	mu    sync.Mutex
	added []core.Duty
	ch    chan core.Duty
}

func (d *testDeadliner) Add(duty core.Duty) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.added = append(d.added, duty)

	return true
}

func (d *testDeadliner) C() <-chan core.Duty {
	return d.ch
}

func (d *testDeadliner) Expire() {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, duty := range d.added {
		d.ch <- duty
	}

	d.ch <- core.Duty{} // Ensure all duty processed before returning.

	d.added = nil
}
