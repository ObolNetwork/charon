// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package aggsigdb_test

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/aggsigdb"
	"github.com/obolnetwork/charon/testutil"
)

func Test_MemDB(t *testing.T) {
	t.Run("MemDB", func(t *testing.T) {
		testMemDB(t, func(deadliner core.Deadliner) core.AggSigDB {
			return aggsigdb.NewMemDBV2(newNoopDeadliner())
		})
	})

	t.Run("MemDBV2", func(t *testing.T) {
		testMemDB(t, func(deadliner core.Deadliner) core.AggSigDB {
			return aggsigdb.NewMemDB(newNoopDeadliner())
		})
	})
}

func testMemDB(t *testing.T, newMemDB func(core.Deadliner) core.AggSigDB) {
	t.Helper()

	t.Run("write read", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		db := newMemDB(newNoopDeadliner())
		go db.Run(ctx)

		testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
		testPubKey := core.PubKey("pubkey")
		testSignedData := testutil.RandomCoreSignature()

		err := db.Store(context.Background(), testDuty, core.SignedDataSet{testPubKey: testSignedData})
		require.NoError(t, err)

		result, err := db.Await(context.Background(), testDuty, testPubKey)
		require.NoError(t, err)

		require.EqualValues(t, testSignedData, result)
	})

	t.Run("write unblocks", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		db := newMemDB(newNoopDeadliner())
		go db.Run(ctx)

		testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
		testPubKey := core.PubKey("pubkey")
		testSignedData := testutil.RandomCoreSignature()

		resChan := make(chan struct {
			result core.SignedData
			err    error
		})

		go func() {
			result, err := db.Await(context.Background(), testDuty, testPubKey)
			resChan <- struct {
				result core.SignedData
				err    error
			}{result: result, err: err}
		}()

		runtime.Gosched()

		err := db.Store(context.Background(), testDuty, core.SignedDataSet{testPubKey: testSignedData})
		require.NoError(t, err)

		res := <-resChan
		require.NoError(t, res.err)
		require.EqualValues(t, testSignedData, res.result)
	})

	t.Run("cancel await", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		db := newMemDB(newNoopDeadliner())
		go db.Run(ctx)

		testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
		testPubKey := core.PubKey("pubkey")

		errChan := make(chan error)
		ctx2, cancel2 := context.WithCancel(context.Background())
		go func() {
			_, err := db.Await(ctx2, testDuty, testPubKey)
			errChan <- err
		}()

		runtime.Gosched()

		cancel2()

		err := <-errChan
		require.Error(t, err)
		require.Equal(t, "context canceled", err.Error())
	})

	t.Run("cancelled await", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		db := newMemDB(newNoopDeadliner())
		go db.Run(ctx)

		testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
		testPubKey := core.PubKey("pubkey")

		ctx2, cancel2 := context.WithCancel(context.Background())
		cancel2()

		_, err := db.Await(ctx2, testDuty, testPubKey)
		require.Error(t, err)
		require.Equal(t, "context canceled", err.Error())
	})

	t.Run("cancel await does not block", func(t *testing.T) {
		// A naive implementation with channels might cause that the main execution loop
		// to block after a await query has been canceled
		ctx, cancel := context.WithCancel(context.Background())

		db := newMemDB(newNoopDeadliner())
		go db.Run(ctx)

		testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
		testPubKey := core.PubKey("pubkey")
		testPubKey2 := core.PubKey("pubkey2")
		testSignedData := testutil.RandomCoreSignature()

		errChan := make(chan error)
		go func() {
			_, err := db.Await(context.Background(), testDuty, testPubKey)
			errChan <- err
		}()

		runtime.Gosched()
		cancel()

		err := <-errChan
		require.Error(t, err)
		require.Equal(t, "database stopped", err.Error())

		err = db.Store(context.Background(), testDuty, core.SignedDataSet{testPubKey: testSignedData})
		require.Error(t, err)

		err = db.Store(context.Background(), testDuty, core.SignedDataSet{testPubKey2: testSignedData})
		require.Error(t, err)
	})

	t.Run("cannot overwrite", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		db := newMemDB(newNoopDeadliner())
		go db.Run(ctx)

		testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
		testPubKey := core.PubKey("pubkey")
		testSignedData := testutil.RandomCoreSignature()
		testSignedData2 := testutil.RandomCoreSignature()

		err := db.Store(context.Background(), testDuty, core.SignedDataSet{testPubKey: testSignedData})
		require.NoError(t, err)

		err = db.Store(context.Background(), testDuty, core.SignedDataSet{testPubKey: testSignedData2})
		require.Error(t, err)
	})

	t.Run("write idempotent", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		db := newMemDB(newNoopDeadliner())
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
	})

	t.Run("write read after stopped", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		db := newMemDB(newNoopDeadliner())
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
		time.Sleep(50 * time.Millisecond)
		runtime.Gosched()

		err = db.Store(context.Background(), testDuty, core.SignedDataSet{testPubKey: testSignedData})
		require.Equal(t, err.Error(), aggsigdb.ErrStopped.Error())

		_, err = db.Await(context.Background(), testDuty, testPubKey)
		require.Equal(t, err.Error(), aggsigdb.ErrStopped.Error())
	})
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
