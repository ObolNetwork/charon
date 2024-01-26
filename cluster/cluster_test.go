// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster_test

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -v -update -clean

const (
	v1_8 = "v1.8.0"
	v1_7 = "v1.7.0"
	v1_6 = "v1.6.0"
	v1_5 = "v1.5.0"
	v1_4 = "v1.4.0"
	v1_3 = "v1.3.0"
	v1_2 = "v1.2.0"
	v1_1 = "v1.1.0"
	v1_0 = "v1.0.0"
)

// TestEncode tests whether charon can correctly encode lock and definition files.
func TestEncode(t *testing.T) {
	for _, version := range cluster.SupportedVersionsForT(t) {
		t.Run(version, func(t *testing.T) {
			vStr := strings.ReplaceAll(version, ".", "_")
			rand.Seed(1)

			const (
				numVals   = 2
				threshold = 3
			)

			opts := []func(d *cluster.Definition){
				func(d *cluster.Definition) {
					d.Version = version
					d.Timestamp = "2022-07-19T18:19:58+02:00" // Make deterministic
					d.DepositAmounts = []eth2p0.Gwei{
						eth2p0.Gwei(16000000000),
						eth2p0.Gwei(16000000000),
					}
				},
			}
			// Definition version prior to v1.5 don't support multiple validator addresses.
			if isAnyVersion(version, v1_0, v1_1, v1_2, v1_3, v1_4) {
				opts = append(opts, cluster.WithLegacyVAddrs(testutil.RandomETHAddress(), testutil.RandomETHAddress()))
			}

			var feeRecipientAddrs, withdrawalAddrs []string
			for i := 0; i < numVals; i++ {
				feeRecipientAddrs = append(feeRecipientAddrs, testutil.RandomETHAddress())
				withdrawalAddrs = append(withdrawalAddrs, testutil.RandomETHAddress())
			}

			definition, err := cluster.NewDefinition(
				"test definition",
				numVals,
				threshold,
				feeRecipientAddrs,
				withdrawalAddrs,
				eth2util.Sepolia.GenesisForkVersionHex,
				cluster.Creator{
					Address:         testutil.RandomETHAddress(),
					ConfigSignature: testutil.RandomSecp256k1Signature(),
				},
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
				opts...,
			)
			testutil.RequireNoError(t, err)

			// Definition version prior to v1.3.0 don't support EIP712 signatures.
			if isAnyVersion(version, v1_0, v1_1, v1_2) {
				for i := range definition.Operators {
					// Set to empty values instead of nil to align with unmarshalled json.
					definition.Operators[i].ConfigSignature = []byte{}
					definition.Operators[i].ENRSignature = []byte{}
				}
			}

			// Definition version prior to v1.4.0 don't support creator.
			if isAnyVersion(version, v1_0, v1_1, v1_2, v1_3) {
				definition.Creator = cluster.Creator{}
			}

			// Definition version prior to v1.8.0 don't support DepositAmounts.
			if isAnyVersion(version, v1_0, v1_1, v1_2, v1_3, v1_4, v1_5, v1_6, v1_7) {
				definition.DepositAmounts = nil
			}

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
						PubKey: testutil.RandomBytes48(),
						PubShares: [][]byte{
							testutil.RandomBytes48(),
							testutil.RandomBytes48(),
						},
						PartialDepositData:  []cluster.DepositData{cluster.RandomDepositData()},
						BuilderRegistration: cluster.RandomRegistration(t, eth2util.Sepolia.Name),
					}, {
						PubKey: testutil.RandomBytes48(),
						PubShares: [][]byte{
							testutil.RandomBytes48(),
							testutil.RandomBytes48(),
						},
						PartialDepositData:  []cluster.DepositData{cluster.RandomDepositData()},
						BuilderRegistration: cluster.RandomRegistration(t, eth2util.Sepolia.Name),
					},
				},
				NodeSignatures: [][]byte{
					testutil.RandomBytes32(),
					testutil.RandomBytes32(),
				},
			}

			// Make sure all the pubkeys are same.
			for i := range lock.Validators {
				for j := range lock.Validators[i].PartialDepositData {
					lock.Validators[i].PartialDepositData[j].PubKey = lock.Validators[i].PubKey
				}
				lock.Validators[i].BuilderRegistration.Message.PubKey = lock.Validators[i].PubKey
			}

			// Lock version prior to v1.6.0 don't support DepositData.
			if isAnyVersion(version, v1_0, v1_1, v1_2, v1_3, v1_4, v1_5) {
				for i := range lock.Validators {
					lock.Validators[i].PartialDepositData = nil
				}
			}

			// Lock version prior to v1.7.0 don't support BuilderRegistration.
			if isAnyVersion(version, v1_0, v1_1, v1_2, v1_3, v1_4, v1_5, v1_6) {
				for i := range lock.Validators {
					lock.Validators[i].BuilderRegistration = cluster.BuilderRegistration{}
				}

				lock.NodeSignatures = nil
			}

			// Lock version v1.8.0 supports multiple PartialDepositData.
			if isAnyVersion(version, v1_8) {
				for i := range lock.Validators {
					dd := cluster.RandomDepositData()
					lock.Validators[i].PartialDepositData = append(lock.Validators[i].PartialDepositData, dd)
				}
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

// TestExamples tests whether charon is backwards compatible with all examples. Note that these examples
// are added manually and not auto-generated.
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
			require.NoError(t, lock.VerifySignatures())
		})
	}

	defFiles, err := filepath.Glob("examples/*definition*")
	require.NoError(t, err)

	for _, file := range defFiles {
		t.Run(filepath.Base(file), func(t *testing.T) {
			b, err := os.ReadFile(file)
			require.NoError(t, err)

			var def cluster.Definition
			err = json.Unmarshal(b, &def)
			require.NoError(t, err)
			require.NoError(t, def.VerifyHashes())
			require.NoError(t, def.VerifySignatures())
		})
	}
}

func TestDefinitionPeers(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 2, 3, 4, 5)
	peers, err := lock.Peers()
	require.NoError(t, err)

	names := []string{"curious-land", "adventurous-age", "witty-industry", "cute-group"}

	for i, peer := range peers {
		require.Equal(t, i, peer.Index)
		require.Equal(t, names[i], peer.Name)
	}
}

func isAnyVersion(version string, list ...string) bool {
	for _, v := range list {
		if version == v {
			return true
		}
	}

	return false
}
