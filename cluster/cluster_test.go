// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster_test

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -v -update -clean

const (
	v1_11 = "v1.11.0"
	v1_10 = "v1.10.0"
	v1_9  = "v1.9.0"
	v1_8  = "v1.8.0"
	v1_7  = "v1.7.0"
	v1_6  = "v1.6.0"
	v1_5  = "v1.5.0"
	v1_4  = "v1.4.0"
	v1_3  = "v1.3.0"
	v1_2  = "v1.2.0"
	v1_1  = "v1.1.0"
	v1_0  = "v1.0.0"
)

// TestEncode tests whether charon can correctly encode lock and definition files.
func TestEncode(t *testing.T) {
	for _, version := range cluster.SupportedVersionsForT(t) {
		t.Run(version, func(t *testing.T) {
			vStr := strings.ReplaceAll(version, ".", "_")
			r := rand.New(rand.NewSource(1))

			const (
				numVals   = 2
				threshold = 3
			)

			opts := []func(d *cluster.Definition){
				func(d *cluster.Definition) {
					d.Version = version
					d.Timestamp = "2022-07-19T18:19:58+02:00" // Make deterministic
				},
			}
			// Definition version prior to v1.5 don't support multiple validator addresses.
			if isAnyVersion(version, v1_0, v1_1, v1_2, v1_3, v1_4) {
				opts = append(opts, cluster.WithLegacyVAddrs(testutil.RandomETHAddressSeed(r), testutil.RandomETHAddressSeed(r)))
			}

			var feeRecipientAddrs, withdrawalAddrs []string
			for range numVals {
				feeRecipientAddrs = append(feeRecipientAddrs, testutil.RandomETHAddressSeed(r))
				withdrawalAddrs = append(withdrawalAddrs, testutil.RandomETHAddressSeed(r))
			}

			var partialAmounts []int
			if isAnyVersion(version, v1_8, v1_9, v1_10, v1_11) {
				partialAmounts = []int{16, 16}
			}

			targetGasLimit := uint(0)
			if isAnyVersion(version, v1_10, v1_11) {
				targetGasLimit = 30000000
			}

			// Generate deterministic ENRs
			_, enr1 := testutil.RandomENR(t, int(r.Int63()))
			_, enr2 := testutil.RandomENR(t, int(r.Int63()))

			definition, err := cluster.NewDefinition(
				"test definition",
				numVals,
				threshold,
				feeRecipientAddrs,
				withdrawalAddrs,
				eth2util.Sepolia.GenesisForkVersionHex,
				cluster.Creator{
					Address:         testutil.RandomETHAddressSeed(r),
					ConfigSignature: testutil.RandomSecp256k1SignatureSeed(r),
				},
				[]cluster.Operator{
					{
						Address:         testutil.RandomETHAddressSeed(r),
						ENR:             enr1.String(),
						ConfigSignature: testutil.RandomSecp256k1SignatureSeed(r),
						ENRSignature:    testutil.RandomSecp256k1SignatureSeed(r),
					},
					{
						Address:         testutil.RandomETHAddressSeed(r),
						ENR:             enr2.String(),
						ConfigSignature: testutil.RandomSecp256k1SignatureSeed(r),
						ENRSignature:    testutil.RandomSecp256k1SignatureSeed(r),
					},
				},
				partialAmounts,
				"abft",
				targetGasLimit,
				false,
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

			// Definition version prior to v1.9.0 don't support ConsensusProtocol.
			if isAnyVersion(version, v1_0, v1_1, v1_2, v1_3, v1_4, v1_5, v1_6, v1_7, v1_8) {
				definition.ConsensusProtocol = ""
			}

			// Definition version prior to v1.10.0 don't support TargetGasLimit.
			if isAnyVersion(version, v1_0, v1_1, v1_2, v1_3, v1_4, v1_5, v1_6, v1_7, v1_8, v1_9) {
				definition.TargetGasLimit = 0
				definition.Compounding = false
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
				SignatureAggregate: testutil.RandomBytes32Seed(r),
				Validators: []cluster.DistValidator{
					{
						PubKey: testutil.RandomBytes48Seed(r),
						PubShares: [][]byte{
							testutil.RandomBytes48Seed(r),
							testutil.RandomBytes48Seed(r),
						},
						PartialDepositData:  []cluster.DepositData{cluster.RandomDepositDataSeed(r)},
						BuilderRegistration: cluster.RandomRegistrationSeed(t, eth2util.Sepolia.Name, r),
					}, {
						PubKey: testutil.RandomBytes48Seed(r),
						PubShares: [][]byte{
							testutil.RandomBytes48Seed(r),
							testutil.RandomBytes48Seed(r),
						},
						PartialDepositData:  []cluster.DepositData{cluster.RandomDepositDataSeed(r)},
						BuilderRegistration: cluster.RandomRegistrationSeed(t, eth2util.Sepolia.Name, r),
					},
				},
				NodeSignatures: [][]byte{
					testutil.RandomBytes32Seed(r),
					testutil.RandomBytes32Seed(r),
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

			// Lock versions v1.8.0 and later support multiple PartialDepositData.
			if !isAnyVersion(version, v1_0, v1_1, v1_2, v1_3, v1_4, v1_5, v1_6, v1_7) {
				for i := range lock.Validators {
					dd := cluster.RandomDepositDataSeed(r)
					dd.PubKey = lock.Validators[i].PubKey
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
			require.NoError(t, lock.VerifySignatures(nil))
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
			require.NoError(t, def.VerifySignatures(nil))
		})
	}
}

func TestDefinitionPeers(t *testing.T) {
	seed := 5
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := cluster.NewForT(t, 2, 3, 4, seed, random)
	peers, err := lock.Peers()
	require.NoError(t, err)

	names := []string{"curious-land", "adventurous-age", "witty-industry", "cute-group"}

	for i, peer := range peers {
		require.Equal(t, i, peer.Index)
		require.Equal(t, names[i], peer.Name)
	}
}

// TestV1x11SafeSignatures tests that v1.11 supports variable-length signatures (Safe multisig).
func TestV1x11SafeSignatures(t *testing.T) {
	r := rand.New(rand.NewSource(1))

	// Create 130-byte signatures (Safe threshold=2: 2 × 65 bytes)
	safeSignature130 := make([]byte, 130)
	_, _ = r.Read(safeSignature130)

	// Create 195-byte signatures (Safe threshold=3: 3 × 65 bytes)
	safeSignature195 := make([]byte, 195)
	_, _ = r.Read(safeSignature195)

	// Create 65-byte EOA signature
	eoaSignature65 := testutil.RandomSecp256k1SignatureSeed(r)

	_, enr1 := testutil.RandomENR(t, 1)
	_, enr2 := testutil.RandomENR(t, 2)

	def, err := cluster.NewDefinition(
		"Safe multisig cluster",
		1,
		2,
		[]string{testutil.RandomETHAddressSeed(r)},
		[]string{testutil.RandomETHAddressSeed(r)},
		eth2util.Sepolia.GenesisForkVersionHex,
		cluster.Creator{
			Address:         testutil.RandomETHAddressSeed(r),
			ConfigSignature: safeSignature130, // Safe threshold=2
		},
		[]cluster.Operator{
			{
				Address:         testutil.RandomETHAddressSeed(r),
				ENR:             enr1.String(),
				ConfigSignature: safeSignature195, // Safe threshold=3
				ENRSignature:    safeSignature130, // Safe threshold=2
			},
			{
				Address:         testutil.RandomETHAddressSeed(r),
				ENR:             enr2.String(),
				ConfigSignature: eoaSignature65, // EOA (65 bytes)
				ENRSignature:    eoaSignature65, // EOA (65 bytes)
			},
		},
		[]int{32}, // Deposit amounts (32 ETH)
		"abft",    // Consensus protocol
		30000000,  // Target gas limit
		false,     // Compounding
		r,         // Random reader
		func(d *cluster.Definition) {
			d.Version = v1_11
			d.Timestamp = "2024-01-01T00:00:00Z"
		},
	)
	require.NoError(t, err)

	// Test SetDefinitionHashes with variable-length signatures
	defWithHashes, err := def.SetDefinitionHashes()
	require.NoError(t, err, "SetDefinitionHashes should succeed with Safe signatures")
	require.NotEmpty(t, defWithHashes.ConfigHash, "ConfigHash should be computed")
	require.NotEmpty(t, defWithHashes.DefinitionHash, "DefinitionHash should be computed")

	// Test JSON marshaling/unmarshaling
	jsonBytes, err := json.Marshal(defWithHashes)
	require.NoError(t, err, "JSON marshal should succeed")

	var unmarshaled cluster.Definition
	err = json.Unmarshal(jsonBytes, &unmarshaled)
	require.NoError(t, err, "JSON unmarshal should succeed")

	// Verify signatures are preserved
	require.Equal(t, 130, len(unmarshaled.Creator.ConfigSignature), "Creator Safe signature length")
	require.Equal(t, 195, len(unmarshaled.Operators[0].ConfigSignature), "Operator 0 config Safe signature length")
	require.Equal(t, 130, len(unmarshaled.Operators[0].ENRSignature), "Operator 0 ENR Safe signature length")
	require.Equal(t, 65, len(unmarshaled.Operators[1].ConfigSignature), "Operator 1 EOA signature length")

	// Test VerifyHashes
	require.NoError(t, defWithHashes.VerifyHashes(), "VerifyHashes should succeed")
}

func isAnyVersion(version string, list ...string) bool {
	return slices.Contains(list, version)
}
