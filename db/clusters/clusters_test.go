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

package clusters_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/db"
	"github.com/obolnetwork/charon/db/clusters"
)

func TestClusters(t *testing.T) {
	t0 := time.Now().Truncate(time.Millisecond)
	bdb := db.OpenForT(t)
	ctx := context.Background()
	cdb := clusters.NewForT(bdb, func() time.Time {
		return t0
	})

	expect := clusters.Cluster{
		ID:        1,
		Hash:      "1234",
		CreatedAt: t0,
	}

	id, err := cdb.Create(ctx, clusters.CreateReq{Hash: expect.Hash})
	require.NoError(t, err)
	require.Equal(t, uint64(1), id)

	actual, ok, err := cdb.Get(ctx, id)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, expect, actual)

	actual, ok, err = cdb.GetByHash(ctx, expect.Hash)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, expect, actual)
}
