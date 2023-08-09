// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package aggsigdb_test

import (
	"context"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/aggsigdb"
	"github.com/obolnetwork/charon/testutil"
)

func TestCoreAggsigdb_MemDB_WriteRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := aggsigdb.NewMemDB(newNoopDeadliner())
	go db.Run(ctx)

	testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
	testPubKey := core.PubKey("pubkey")
	testSignedData := testutil.RandomCoreSignature()

	err := db.Store(context.Background(), testDuty, core.SignedDataSet{testPubKey: testSignedData})
	require.NoError(t, err)

	result, err := db.Await(context.Background(), testDuty, testPubKey)
	require.NoError(t, err)

	require.EqualValues(t, testSignedData, result)
}

func TestCoreAggsigdb_MemDB_WriteUnblocks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := aggsigdb.NewMemDB(newNoopDeadliner())
	go db.Run(ctx)

	testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
	testPubKey := core.PubKey("pubkey")
	testSignedData := testutil.RandomCoreSignature()

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()

		result, err := db.Await(context.Background(), testDuty, testPubKey)
		require.NoError(t, err)
		require.EqualValues(t, testSignedData, result)
	}()

	runtime.Gosched()

	err := db.Store(context.Background(), testDuty, core.SignedDataSet{testPubKey: testSignedData})
	require.NoError(t, err)

	wg.Wait()
}

func TestCoreAggsigdb_MemDB_CancelAwait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db := aggsigdb.NewMemDB(newNoopDeadliner())
	go db.Run(ctx)

	testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
	testPubKey := core.PubKey("pubkey")

	wg := sync.WaitGroup{}
	wg.Add(1)

	ctx2, cancel2 := context.WithCancel(context.Background())
	go func() {
		defer wg.Done()

		_, err := db.Await(ctx2, testDuty, testPubKey)
		require.Error(t, err)
		require.Equal(t, err.Error(), "context canceled")
	}()

	runtime.Gosched()

	cancel2()
	wg.Wait()
}

func TestCoreAggsigdb_MemDB_CancelledAwait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db := aggsigdb.NewMemDB(newNoopDeadliner())
	go db.Run(ctx)

	testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
	testPubKey := core.PubKey("pubkey")

	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()

	_, err := db.Await(ctx2, testDuty, testPubKey)
	require.Error(t, err)
	require.Equal(t, err.Error(), "context canceled")
}

func TestCoreAggsigdb_MemDB_CancelAwaitDoesnotblock(t *testing.T) {
	// A naive implementation with channels might cause that the main execution loop
	// to block after a await query has been canceled
	ctx, cancel := context.WithCancel(context.Background())

	db := aggsigdb.NewMemDB(newNoopDeadliner())
	go db.Run(ctx)

	testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
	testPubKey := core.PubKey("pubkey")
	testPubKey2 := core.PubKey("pubkey2")
	testSignedData := testutil.RandomCoreSignature()

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()

		_, err := db.Await(context.Background(), testDuty, testPubKey)
		require.Error(t, err)
		require.Equal(t, err.Error(), "database stopped")
	}()

	runtime.Gosched()
	cancel()
	wg.Wait()

	err := db.Store(context.Background(), testDuty, core.SignedDataSet{testPubKey: testSignedData})
	require.Error(t, err)

	err = db.Store(context.Background(), testDuty, core.SignedDataSet{testPubKey2: testSignedData})
	require.Error(t, err)
}

func TestCoreAggsigdb_MemDB_CannotOverwrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := aggsigdb.NewMemDB(newNoopDeadliner())
	go db.Run(ctx)

	testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
	testPubKey := core.PubKey("pubkey")
	testSignedData := testutil.RandomCoreSignature()
	testSignedData2 := testutil.RandomCoreSignature()

	err := db.Store(context.Background(), testDuty, core.SignedDataSet{testPubKey: testSignedData})
	require.NoError(t, err)

	err = db.Store(context.Background(), testDuty, core.SignedDataSet{testPubKey: testSignedData2})
	require.Error(t, err)
}

func TestCoreAggsigdb_MemDB_WriteIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := aggsigdb.NewMemDB(newNoopDeadliner())
	go db.Run(ctx)

	testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
	testPubKey := core.PubKey("pubkey")
	testSignedData := testutil.RandomCoreSignature()

	err := db.Store(context.Background(), testDuty, core.SignedDataSet{testPubKey: testSignedData})
	require.NoError(t, err)

	err = db.Store(context.Background(), testDuty, core.SignedDataSet{testPubKey: testSignedData})
	require.NoError(t, err)

	result, err := db.Await(context.Background(), testDuty, testPubKey)
	require.NoError(t, err)
	require.EqualValues(t, testSignedData, result)
}

func TestCoreAggsigdb_MemDB_WriteReadAftersStopped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	db := aggsigdb.NewMemDB(newNoopDeadliner())
	go db.Run(ctx)

	testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
	testPubKey := core.PubKey("pubkey")
	testSignedData := testutil.RandomCoreSignature()

	err := db.Store(context.Background(), testDuty, core.SignedDataSet{testPubKey: testSignedData})
	require.NoError(t, err)

	result, err := db.Await(context.Background(), testDuty, testPubKey)
	require.NoError(t, err)
	require.EqualValues(t, testSignedData, result)

	cancel()

	err = db.Store(context.Background(), testDuty, core.SignedDataSet{testPubKey: testSignedData})
	require.Equal(t, err.Error(), aggsigdb.ErrStopped.Error())

	_, err = db.Await(context.Background(), testDuty, testPubKey)
	require.Equal(t, err.Error(), aggsigdb.ErrStopped.Error())
}

func newNoopDeadliner() core.Deadliner {
	return noopDeadliner{}
}

type noopDeadliner struct{}

func (noopDeadliner) Add(core.Duty) bool {
	return true
}

func (noopDeadliner) C() <-chan core.Duty {
	return make(chan core.Duty)
}
