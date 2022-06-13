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
	"os"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -v -update

func TestEncode(t *testing.T) {
	rand.Seed(0)

	definition := cluster.NewDefinition(
		"test definition",
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

	definition.OperatorSignatures = [][]byte{
		testutil.RandomBytes32(),
		testutil.RandomBytes32(),
	}

	t.Run("definition_yaml", func(t *testing.T) {
		jsonBytes, err := json.Marshal(definition)
		require.NoError(t, err)
		yamlBytes, err := yaml.JSONToYAML(jsonBytes)
		require.NoError(t, err)
		testutil.RequireGoldenBytes(t, yamlBytes)
	})

	t.Run("definition_json", func(t *testing.T) {
		testutil.RequireGoldenJSON(t, definition)
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
	require.Equal(t, definition, definition2)

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

	t.Run("lock_json", func(t *testing.T) {
		testutil.RequireGoldenJSON(t, lock)
	})

	t.Run("lock_yaml", func(t *testing.T) {
		jsonBytes, err := json.Marshal(lock)
		require.NoError(t, err)
		yamlBytes, err := yaml.JSONToYAML(jsonBytes)
		require.NoError(t, err)
		testutil.RequireGoldenBytes(t, yamlBytes)
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

// TestBackwardsCompatability ensures that the current code is backwards compatible
// with previous versions stored in testdata.
func TestBackwardsCompatability(t *testing.T) {
	tests := []struct {
		version string
	}{
		{
			version: "v1.0.0",
		},
		// Note: Add testdata files for newer versions when bumped.
	}
	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			suffix := strings.ReplaceAll(test.version, ".", "_")

			b, err := os.ReadFile(fmt.Sprintf("testdata/definition_%s.json", suffix))
			require.NoError(t, err)

			var def cluster.Definition
			require.NoError(t, json.Unmarshal(b, &def))

			b, err = os.ReadFile(fmt.Sprintf("testdata/lock_%s.json", suffix))
			require.NoError(t, err)

			var lock cluster.Lock
			require.NoError(t, json.Unmarshal(b, &lock))
		})
	}
}
