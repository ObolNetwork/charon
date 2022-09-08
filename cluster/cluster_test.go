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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -v -update -clean

func TestEncode(t *testing.T) {
	for _, version := range cluster.SupportedVersionsForT(t) {
		vStr := strings.ReplaceAll(version, ".", "_")
		rand.Seed(1)

		definition := cluster.NewDefinition(
			"test definition",
			2,
			3,
			testutil.RandomETHAddress(),
			testutil.RandomETHAddress(),
			"0x00000002",
			[]cluster.Operator{
				{
					Address:         testutil.RandomETHAddress(),
					ENR:             fmt.Sprintf("enr://%x", testutil.RandomBytes32()),
					ConfigSignature: testutil.RandomBytes32(),
					ENRSignature:    testutil.RandomBytes32(),
				},
				{
					Address:         testutil.RandomETHAddress(),
					ENR:             fmt.Sprintf("enr://%x", testutil.RandomBytes32()),
					ConfigSignature: testutil.RandomBytes32(),
					ENRSignature:    testutil.RandomBytes32(),
				},
			},
			rand.New(rand.NewSource(0)),
		)
		definition.Version = version
		definition.Timestamp = "2022-07-19T18:19:58+02:00" // Make deterministic

		t.Run("definition_json_"+vStr, func(t *testing.T) {
			testutil.RequireGoldenJSON(t, definition,
				testutil.WithFilename("cluster_definition_"+vStr+".json"))
		})

		hash1, err := definition.HashTreeRoot()
		require.NoError(t, err)
		hash2, err := definition.HashTreeRoot()
		require.NoError(t, err)
		require.Equal(t, hash1, hash2)

		b1, err := json.Marshal(definition)
		require.NoError(t, err)

		var definition2 cluster.Definition
		err = json.Unmarshal(b1, &definition2)
		require.NoError(t, err)

		b2, err := json.Marshal(definition2)
		require.NoError(t, err)

		require.Equal(t, b1, b2)

		lock := cluster.Lock{
			Definition:         definition,
			SignatureAggregate: testutil.RandomBytes32(),
			Validators: []cluster.DistValidator{
				{
					PubKey: testutil.RandomETHAddress(),
					PubShares: [][]byte{
						testutil.RandomBytes32(),
						testutil.RandomBytes32(),
					},
				}, {
					PubKey: testutil.RandomETHAddress(),
					PubShares: [][]byte{
						testutil.RandomBytes32(),
						testutil.RandomBytes32(),
					},
				},
			},
		}

		t.Run("_lock_json"+vStr, func(t *testing.T) {
			testutil.RequireGoldenJSON(t, lock,
				testutil.WithFilename("cluster_lock_"+vStr+".json"))
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
	}
}

func TestUnsupportedVersion(t *testing.T) {
	var def cluster.Definition
	err := json.Unmarshal([]byte(`{"version":"invalid"}`), &def)
	require.ErrorContains(t, err, "unsupported definition version")

	var lock cluster.Lock
	err = json.Unmarshal([]byte(`{"cluster_definition":{"version":"invalid"}}`), &lock)
	require.ErrorContains(t, err, "unsupported definition version")
}
