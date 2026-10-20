// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package aggsigdb

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

func TestDutyExpiration(t *testing.T) {
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())

	deadliner := newTestDeadliner()
	db := NewMemDB(deadliner)

	wg.Go(func() {
		db.Run(ctx)
	})

	slot := uint64(99)
	duty := core.NewAttesterDuty(slot)
	pubkey := testutil.RandomCorePubKey(t)
	sig := testutil.RandomCoreSignature()

	err := db.Store(ctx, duty, core.SignedDataSet{pubkey: sig})
	require.NoError(t, err)

	resp, err := db.Await(ctx, duty, pubkey, core.AwaitOpts{})
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

	require.Empty(t, db.generalDuties.data)
	require.Empty(t, db.generalDuties.keysByDuty)
}

func TestCancelledQuery(t *testing.T) {
	ctx := t.Context()

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
		_, err := db.Await(qctx, duty, pubkey, core.AwaitOpts{})
		errCh <- err

		wg.Done()
	}()

	require.Equal(t, 1, <-queryCount)

	wg.Go(func() {
		_, err := db.Await(qctx, duty, pubkey, core.AwaitOpts{})
		errCh <- err
	})

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

func (d *testDeadliner) Add(duty core.Duty) core.DeadlineStatus {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.added = append(d.added, duty)

	return core.DeadlineScheduled
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

// TestProposerPreferencesReorg verifies that aggregates for the same proposer preferences duty
// and pubkey but different message roots (a reorg changed the dependent root and a new aggregate
// reached threshold) are stored independently instead of erroring as mismatching data.
func TestProposerPreferencesReorg(t *testing.T) {
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())

	db := NewMemDB(newTestDeadliner())

	wg.Go(func() {
		db.Run(ctx)
	})

	pubkey := testutil.RandomCorePubKey(t)

	prefA := testutil.RandomProposerPreferences()
	duty := core.NewProposerPreferencesDuty(uint64(prefA.Message.ProposalSlot))

	// Same slot and validator, different dependent root (reorg).
	prefB := testutil.RandomProposerPreferences()
	prefB.Message.ProposalSlot = prefA.Message.ProposalSlot
	prefB.Message.ValidatorIndex = prefA.Message.ValidatorIndex

	err := db.Store(ctx, duty, core.SignedDataSet{pubkey: core.NewSignedProposerPreferences(prefA)})
	require.NoError(t, err)

	err = db.Store(ctx, duty, core.SignedDataSet{pubkey: core.NewSignedProposerPreferences(prefB)})
	require.NoError(t, err)

	cancel()
	wg.Wait()

	require.Len(t, db.propPrefDuties.data, 2)
}

// TestAwaitBuilderRequestAuth verifies that builder request auths for several builders of the
// same duty and pubkey are stored independently and awaited by the builder's auth data.
func TestAwaitBuilderRequestAuth(t *testing.T) {
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		wg.Wait()
	}()

	db := NewMemDB(newTestDeadliner())

	wg.Go(func() {
		db.Run(ctx)
	})

	pubkey := testutil.RandomCorePubKey(t)

	authA := testutil.RandomSignedBuilderRequestAuth()
	authA.Message.Data = []byte("relay-a.example.com")
	duty := core.NewBuilderPreferencesDuty(uint64(authA.Message.Slot))

	authB := testutil.RandomSignedBuilderRequestAuth()
	authB.Message.Data = []byte("relay-b.example.com")
	authB.Message.Slot = authA.Message.Slot

	// Awaiting the duty without naming a builder is an error.
	_, err := db.Await(ctx, duty, pubkey, core.AwaitOpts{})
	require.ErrorContains(t, err, "builder host required")

	// Awaiting builder B blocks until its aggregate is stored, not builder A's.
	awaited := make(chan core.SignedData, 1)

	wg.Go(func() {
		data, err := db.Await(ctx, duty, pubkey, core.AwaitOpts{BuilderHost: string(authB.Message.Data)})
		if err == nil {
			awaited <- data
		}
	})

	require.NoError(t, db.Store(ctx, duty, core.SignedDataSet{pubkey: core.NewSignedBuilderRequestAuth(authA)}))
	require.NoError(t, db.Store(ctx, duty, core.SignedDataSet{pubkey: core.NewSignedBuilderRequestAuth(authB)}))

	select {
	case data := <-awaited:
		require.Equal(t, core.NewSignedBuilderRequestAuth(authB), data)
	case <-time.After(time.Second):
		require.Fail(t, "builder B's auth not returned")
	}

	// Builder A's aggregate is returned for its own auth data.
	data, err := db.Await(ctx, duty, pubkey, core.AwaitOpts{BuilderHost: string(authA.Message.Data)})
	require.NoError(t, err)
	require.Equal(t, core.NewSignedBuilderRequestAuth(authA), data)
}

// TestAwaitOptsValidation verifies which duties can be awaited and the options they require;
// options that don't apply to a duty are ignored. A valid query of a database that isn't
// running blocks until the context expires.
func TestAwaitOptsValidation(t *testing.T) {
	db := NewMemDB(newTestDeadliner())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name string
		duty core.Duty
		opts core.AwaitOpts
		err  string
	}{
		{name: "randao", duty: core.NewRandaoDuty(1)},
		{name: "randao with subcommittee", duty: core.NewRandaoDuty(1), opts: core.AwaitOpts{SubcommIdx: 1}},
		{name: "randao with builder", duty: core.NewRandaoDuty(1), opts: core.AwaitOpts{BuilderHost: "relay-a.example.com"}},
		{name: "sync contribution", duty: core.NewSyncContributionDuty(1), opts: core.AwaitOpts{SubcommIdx: 2}},
		{name: "sync contribution with builder", duty: core.NewSyncContributionDuty(1), opts: core.AwaitOpts{SubcommIdx: 2, BuilderHost: "relay-a.example.com"}},
		{name: "builder preferences", duty: core.NewBuilderPreferencesDuty(1), opts: core.AwaitOpts{BuilderHost: "relay-a.example.com"}},
		{name: "builder preferences without builder", duty: core.NewBuilderPreferencesDuty(1), err: "builder host required"},
		{name: "builder preferences with subcommittee", duty: core.NewBuilderPreferencesDuty(1), opts: core.AwaitOpts{BuilderHost: "relay-a.example.com", SubcommIdx: 1}},
		{name: "proposer preferences", duty: core.NewProposerPreferencesDuty(1), err: errNotAwaitable.Error()},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := db.Await(ctx, test.duty, testutil.RandomCorePubKey(t), test.opts)
			if test.err != "" {
				require.ErrorContains(t, err, test.err)
			} else {
				require.ErrorIs(t, err, context.Canceled)
			}
		})
	}
}
