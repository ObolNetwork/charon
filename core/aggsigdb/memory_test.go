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
