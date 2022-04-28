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

package cluster_test

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -clean -update

func TestEncode(t *testing.T) {
	rand.Seed(0)

	params := cluster.NewParams(
		"test params",
		2,
		3,
		testutil.RandomETHAddress(),
		testutil.RandomETHAddress(),
		"0x00000002",
		[]cluster.Operator{
			{
				Address:      testutil.RandomETHAddress(),
				ENR:          fmt.Sprintf("enr://%x", testutil.RandomBytes32()),
				Nonce:        0,
				ENRSignature: testutil.RandomBytes32(),
			},
			{
				Address:      testutil.RandomETHAddress(),
				ENR:          fmt.Sprintf("enr://%x", testutil.RandomBytes32()),
				Nonce:        1,
				ENRSignature: testutil.RandomBytes32(),
			},
		},
		rand.New(rand.NewSource(0)),
	)

	t.Run("params_json", func(t *testing.T) {
		testutil.RequireGoldenJSON(t, params)
	})

	hash1, err := params.HashTreeRoot()
	require.NoError(t, err)
	hash2, err := params.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, hash1, hash2)

	b1, err := json.Marshal(params)
	require.NoError(t, err)

	var params2 cluster.Params
	err = json.Unmarshal(b1, &params2)
	require.NoError(t, err)

	b2, err := json.Marshal(params2)
	require.NoError(t, err)

	require.Equal(t, b1, b2)
	require.Equal(t, params, params2)

	lock := cluster.Lock{
		Params:             params,
		SignatureAggregate: testutil.RandomBytes32(),
		Validators: []cluster.DistValidator{
			{
				PubKey: testutil.RandomETHAddress(),
				Verifiers: [][]byte{
					testutil.RandomBytes32(),
					testutil.RandomBytes32(),
				},
			}, {
				PubKey: testutil.RandomETHAddress(),
				Verifiers: [][]byte{
					testutil.RandomBytes32(),
					testutil.RandomBytes32(),
				},
			},
		},
	}

	t.Run("lock_json", func(t *testing.T) {
		testutil.RequireGoldenJSON(t, lock)
	})

	hash1, err = lock.HashTreeRoot()
	require.NoError(t, err)
	hash2, err = lock.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, hash1, hash2)

	b1, err = json.Marshal(lock)
	require.NoError(t, err)

	var lock2 cluster.Lock
	err = json.Unmarshal(b1, &lock2)
	require.NoError(t, err)

	b2, err = json.Marshal(lock2)
	require.NoError(t, err)

	require.Equal(t, b1, b2)
	require.Equal(t, lock, lock2)
}
