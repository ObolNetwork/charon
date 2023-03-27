// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

	require.Zero(t, db.data.count)
	require.Zero(t, db.keysByDuty.count)
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

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		_, err := db.Await(qctx, duty, pubkey)
		require.ErrorIs(t, err, context.Canceled)
		wg.Done()
	}()
	require.Equal(t, 1, <-queryCount)

	wg.Add(1)
	go func() {
		_, err := db.Await(qctx, duty, pubkey)
		require.ErrorIs(t, err, context.Canceled)
		wg.Done()
	}()
	require.Equal(t, 2, <-queryCount)

	// Cancel queries
	qcancel()
	wg.Wait()

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
