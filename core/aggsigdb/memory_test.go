// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	db := aggsigdb.NewMemDB()
	db.Run(context.Background())

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
	db := aggsigdb.NewMemDB()
	db.Run(context.Background())

	testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
	testPubKey := core.PubKey("pubkey")
	testAggSignedData := core.AggSignedData{
		Data:      []byte("test data"),
		Signature: []byte("test signature"),
	}

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		result, err := db.Await(context.Background(), testDuty, testPubKey)
		require.NoError(t, err)
		require.EqualValues(t, testAggSignedData, result)
		wg.Done()
	}()

	runtime.Gosched()

	err := db.Store(context.Background(), testDuty, testPubKey, testAggSignedData)
	require.NoError(t, err)

	wg.Wait()
}

func TestCoreAggsigdb_MemDB_CancelAwait(t *testing.T) {
	db := aggsigdb.NewMemDB()
	db.Run(context.Background())

	testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
	testPubKey := core.PubKey("pubkey")

	wg := sync.WaitGroup{}
	wg.Add(1)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		_, err := db.Await(ctx, testDuty, testPubKey)
		require.Error(t, err)
		require.Equal(t, err.Error(), "context canceled")
		wg.Done()
	}()

	runtime.Gosched()

	cancel()
	wg.Wait()
}

func TestCoreAggsigdb_MemDB_CancelAwaitDoesnotblock(t *testing.T) {
	// A naive implementation with channels might cause that the main execution loop
	// to block after a await query has been canceled
	db := aggsigdb.NewMemDB()
	db.Run(context.Background())

	testDuty := core.Duty{Slot: 10, Type: core.DutyProposer}
	testPubKey := core.PubKey("pubkey")
	testPubKey2 := core.PubKey("pubkey2")
	testAggSignedData := core.AggSignedData{
		Data:      []byte("test data"),
		Signature: []byte("test signature"),
	}

	wg := sync.WaitGroup{}
	wg.Add(1)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		_, err := db.Await(ctx, testDuty, testPubKey)
		require.Error(t, err)
		require.Equal(t, err.Error(), "context canceled")
		wg.Done()
	}()

	runtime.Gosched()

	cancel()

	wg.Wait()
	err := db.Store(context.Background(), testDuty, testPubKey, testAggSignedData)
	require.NoError(t, err)

	err = db.Store(context.Background(), testDuty, testPubKey2, testAggSignedData)
	require.NoError(t, err)
}

func TestCoreAggsigdb_MemDB_CannotOverwrite(t *testing.T) {
	db := aggsigdb.NewMemDB()
	db.Run(context.Background())

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
	db := aggsigdb.NewMemDB()
	db.Run(context.Background())

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
