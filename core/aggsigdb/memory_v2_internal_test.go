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

func TestDutyExpirationV2(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	deadliner := newTestDeadliner()
	db := NewMemDBV2(deadliner)
	go db.Run(ctx)

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

	var dataLen int
	var keysByDutyLen int

	db.data.Range(func(_, _ any) bool {
		dataLen++
		return true
	})

	db.keysByDuty.Range(func(_, _ any) bool {
		keysByDutyLen++
		return true
	})

	require.Zero(t, dataLen)
	require.Zero(t, keysByDutyLen)
}

func TestCancelledQueryV2(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db := NewMemDBV2(newTestDeadliner())

	go db.Run(ctx)

	slot := uint64(99)
	duty := core.NewAttesterDuty(slot)
	pubkey := testutil.RandomCorePubKey(t)
	sig := testutil.RandomCoreSignature()

	// Enqueue 2 queries and wait for them to be blocked.
	qctx, qcancel := context.WithCancel(ctx)

	var wg sync.WaitGroup
	wg.Add(2)

	awaitAmt := 2

	errStore := make([]error, awaitAmt)
	for idx := 0; idx < awaitAmt; idx++ {
		idx := idx
		go func() {
			_, err := db.Await(qctx, duty, pubkey)
			errStore[idx] = err
			wg.Done()
		}()
	}

	// Cancel queries
	qcancel()
	wg.Wait()

	for _, err := range errStore {
		require.ErrorIs(t, err, context.Canceled)
	}

	// Store something and ensure no blocked queries
	err := db.Store(ctx, duty, core.SignedDataSet{pubkey: sig})
	require.NoError(t, err)
}
