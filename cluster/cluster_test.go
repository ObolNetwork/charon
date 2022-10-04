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
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -v -update -clean

func TestEncode(t *testing.T) {
	for _, version := range cluster.SupportedVersionsForT(t) {
		t.Run(version, func(t *testing.T) {
			vStr := strings.ReplaceAll(version, ".", "_")
			rand.Seed(1)

			definition, err := cluster.NewDefinition(
				"test definition",
				2,
				3,
				testutil.RandomETHAddress(),
				testutil.RandomETHAddress(),
				eth2util.Sepolia.ForkVersionHex,
				[]cluster.Operator{
					{
						Address:         testutil.RandomETHAddress(),
						ENR:             fmt.Sprintf("enr://%x", testutil.RandomBytes32()),
						ConfigSignature: testutil.RandomSecp256k1Signature(),
						ENRSignature:    testutil.RandomSecp256k1Signature(),
					},
					{
						Address:         testutil.RandomETHAddress(),
						ENR:             fmt.Sprintf("enr://%x", testutil.RandomBytes32()),
						ConfigSignature: testutil.RandomSecp256k1Signature(),
						ENRSignature:    testutil.RandomSecp256k1Signature(),
					},
				},
				rand.New(rand.NewSource(0)),
			)
			require.NoError(t, err)
			definition.Version = version
			definition.Timestamp = "2022-07-19T18:19:58+02:00" // Make deterministic

			t.Run("definition_json_"+vStr, func(t *testing.T) {
				testutil.RequireGoldenJSON(t, definition,
					testutil.WithFilename("cluster_definition_"+vStr+".json"))
			})

			b1, err := json.Marshal(definition)
			testutil.RequireNoError(t, err)

			var definition2 cluster.Definition
			err = json.Unmarshal(b1, &definition2)
			require.NoError(t, err)

			b2, err := json.Marshal(definition2)
			require.NoError(t, err)

			require.Equal(t, b1, b2)

			definition, err = definition.SetDefinitionHashes() // Add hashes to locally created definition.
			require.NoError(t, err)
			require.Equal(t, definition, definition2)

			lock := cluster.Lock{
				Definition:         definition,
				SignatureAggregate: testutil.RandomBytes32(),
				Validators: []cluster.DistValidator{
					{
						PubKey: testutil.RandomBytes20(), // TODO(corver): Change sigs to Bytes48.
						PubShares: [][]byte{
							testutil.RandomBytes32(), // TODO(corver): Change sigs to Bytes48.
							testutil.RandomBytes32(),
						},
					}, {
						PubKey: testutil.RandomBytes20(),
						PubShares: [][]byte{
							testutil.RandomBytes32(),
							testutil.RandomBytes32(),
						},
					},
				},
			}

			t.Run("lock_json_"+vStr, func(t *testing.T) {
				testutil.RequireGoldenJSON(t, lock,
					testutil.WithFilename("cluster_lock_"+vStr+".json"))
			})

			b1, err = json.Marshal(lock)
			require.NoError(t, err)

			var lock2 cluster.Lock
			err = json.Unmarshal(b1, &lock2)
			require.NoError(t, err)

			b2, err = json.Marshal(lock2)
			require.NoError(t, err)

			require.Equal(t, b1, b2)

			lock, err = lock.SetLockHash()
			require.NoError(t, err)
			require.Equal(t, lock, lock2)
		})
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

// TestExamples tests whether charon is backwards compatible with all examples.
func TestExamples(t *testing.T) {
	lockFiles, err := filepath.Glob("examples/*lock*")
	require.NoError(t, err)

	for _, file := range lockFiles {
		t.Run(filepath.Base(file), func(t *testing.T) {
			b, err := os.ReadFile(file)
			require.NoError(t, err)

			var lock cluster.Lock
			err = json.Unmarshal(b, &lock)
			require.NoError(t, err)

			require.NoError(t, lock.VerifyHashes())
		})
	}
}
