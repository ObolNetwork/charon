// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	deadliner := newTestDeadliner()
	db := NewMemDB(deadliner)

	wg.Add(1)
	go func() {
		defer wg.Done()

		db.Run(ctx)
	}()

	slot := uint64(99)
	duty := core.NewAttesterDuty(slot)
	pubkey := testutil.RandomCorePubKey(t)
	sig := testutil.RandomCoreSignature()

	err := db.Store(ctx, duty, core.SignedDataSet{pubkey: sig})
	require.NoError(t, err)

	resp, err := db.Await(ctx, duty, pubkey)
	require.NoError(t, err)
	require.Equal(t, sig, resp)

	deadliner.Expire()

	// Why?
	// aggsigdb relies on channels and a single executing goroutine to synchronize access to its internal data structure
	// and while this is cool and useful, it makes our life hard in this test.
	// So what I'm doing here is to explicitly cancel the context
	// And wait till go routine is closed
	cancel()
	wg.Wait()

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

	slot := uint64(99)
	duty := core.NewAttesterDuty(slot)
	pubkey := testutil.RandomCorePubKey(t)
	sig := testutil.RandomCoreSignature()

	// Enqueue 2 queries and wait for them to be blocked.
	qctx, qcancel := context.WithCancel(ctx)

	var wg sync.WaitGroup

	wg.Add(1)
	errCh := make(chan error, 2)
	go func() {
		_, err := db.Await(qctx, duty, pubkey)
		errCh <- err
		wg.Done()
	}()
	require.Equal(t, 1, <-queryCount)

	wg.Add(1)
	go func() {
		_, err := db.Await(qctx, duty, pubkey)
		errCh <- err
		wg.Done()
	}()
	require.Equal(t, 2, <-queryCount)

	// Cancel queries
	qcancel()
	wg.Wait()

	err := <-errCh
	require.ErrorIs(t, err, context.Canceled)
	err = <-errCh
	require.ErrorIs(t, err, context.Canceled)

	// Store something and ensure no blocked queries
	err = db.Store(ctx, duty, core.SignedDataSet{pubkey: sig})
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
