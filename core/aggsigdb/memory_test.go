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

package aggsigdb_test

import (
	"context"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/aggsigdb"
)

func TestCoreAggsigdb_MemDB_WriteRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := aggsigdb.NewMemDB()
	go db.Run(ctx)

	testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
	testPubKey := core.PubKey("pubkey")
	testAggSignedData := core.AggSignedData{
		Data:      []byte("test data"),
		Signature: []byte("test signature"),
	}

	err := db.Store(context.Background(), testDuty, testPubKey, testAggSignedData)
	require.NoError(t, err)

	result, err := db.Await(context.Background(), testDuty, testPubKey)
	require.NoError(t, err)

	require.EqualValues(t, testAggSignedData, result)
}

func TestCoreAggsigdb_MemDB_WriteUnblocks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := aggsigdb.NewMemDB()
	go db.Run(ctx)

	testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
	testPubKey := core.PubKey("pubkey")
	testAggSignedData := core.AggSignedData{
		Data:      []byte("test data"),
		Signature: []byte("test signature"),
	}

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()

		result, err := db.Await(context.Background(), testDuty, testPubKey)
		require.NoError(t, err)
		require.EqualValues(t, testAggSignedData, result)
	}()

	runtime.Gosched()

	err := db.Store(context.Background(), testDuty, testPubKey, testAggSignedData)
	require.NoError(t, err)

	wg.Wait()
}

func TestCoreAggsigdb_MemDB_CancelAwait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db := aggsigdb.NewMemDB()
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

	db := aggsigdb.NewMemDB()
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

	db := aggsigdb.NewMemDB()
	go db.Run(ctx)

	testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
	testPubKey := core.PubKey("pubkey")
	testPubKey2 := core.PubKey("pubkey2")
	testAggSignedData := core.AggSignedData{
		Data:      []byte("test data"),
		Signature: []byte("test signature"),
	}

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

	err := db.Store(context.Background(), testDuty, testPubKey, testAggSignedData)
	require.Error(t, err)

	err = db.Store(context.Background(), testDuty, testPubKey2, testAggSignedData)
	require.Error(t, err)
}

func TestCoreAggsigdb_MemDB_CannotOverwrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := aggsigdb.NewMemDB()
	go db.Run(ctx)

	testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
	testPubKey := core.PubKey("pubkey")
	testAggSignedData := core.AggSignedData{
		Data:      []byte("test data"),
		Signature: []byte("test signature"),
	}
	testAggSignedData2 := core.AggSignedData{
		Data:      []byte("test data 2"),
		Signature: []byte("test signature 2"),
	}

	err := db.Store(context.Background(), testDuty, testPubKey, testAggSignedData)
	require.NoError(t, err)

	err = db.Store(context.Background(), testDuty, testPubKey, testAggSignedData2)
	require.Error(t, err)
}

func TestCoreAggsigdb_MemDB_WriteIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := aggsigdb.NewMemDB()
	go db.Run(ctx)

	testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
	testPubKey := core.PubKey("pubkey")
	testAggSignedData := core.AggSignedData{
		Data:      []byte("test data"),
		Signature: []byte("test signature"),
	}

	err := db.Store(context.Background(), testDuty, testPubKey, testAggSignedData)
	require.NoError(t, err)

	err = db.Store(context.Background(), testDuty, testPubKey, testAggSignedData)
	require.NoError(t, err)

	result, err := db.Await(context.Background(), testDuty, testPubKey)
	require.NoError(t, err)
	require.EqualValues(t, testAggSignedData, result)
}

func TestCoreAggsigdb_MemDB_WriteReadAftersStopped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	db := aggsigdb.NewMemDB()
	go db.Run(ctx)

	testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
	testPubKey := core.PubKey("pubkey")
	testAggSignedData := core.AggSignedData{
		Data:      []byte("test data"),
		Signature: []byte("test signature"),
	}

	err := db.Store(context.Background(), testDuty, testPubKey, testAggSignedData)
	require.NoError(t, err)

	result, err := db.Await(context.Background(), testDuty, testPubKey)
	require.NoError(t, err)
	require.EqualValues(t, testAggSignedData, result)

	cancel()

	err = db.Store(context.Background(), testDuty, testPubKey, testAggSignedData)
	require.Equal(t, err.Error(), aggsigdb.ErrStopped.Error())

	_, err = db.Await(context.Background(), testDuty, testPubKey)
	require.Equal(t, err.Error(), aggsigdb.ErrStopped.Error())
}
