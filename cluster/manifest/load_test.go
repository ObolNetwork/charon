// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package manifest_test

import (
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
	"github.com/obolnetwork/charon/testutil"
)

func TestLoadLegacy(t *testing.T) {
	for _, version := range cluster.SupportedVersionsForT(t) {
		t.Run(version, func(t *testing.T) {
			testLoadLegacy(t, version)
		})
	}
}

func TestLoadManifest(t *testing.T) {
	legacyLockFile := "testdata/lock.json"
	lockJSON, err := os.ReadFile(legacyLockFile)
	require.NoError(t, err)

	var lock cluster.Lock
	testutil.RequireNoError(t, json.Unmarshal(lockJSON, &lock))

	legacyLock, err := manifest.NewLegacyLockForT(t, lock)
	require.NoError(t, err)

	dag := &manifestpb.SignedMutationList{Mutations: []*manifestpb.SignedMutation{legacyLock}}
	cluster, err := manifest.Materialise(dag)
	require.NoError(t, err)

	b, err := proto.Marshal(dag)
	require.NoError(t, err)

	manifestFile := path.Join(t.TempDir(), "cluster-manifest.pb")
	require.NoError(t, os.WriteFile(manifestFile, b, 0o644))

	tests := []struct {
		name           string
		manifestFile   string
		legacyLockFile string
		errorMsg       string
	}{
		{
			name:     "no file",
			errorMsg: "no file found",
		},
		{
			name:         "only manifest",
			manifestFile: manifestFile,
		},
		{
			name:           "only legacy lock",
			legacyLockFile: legacyLockFile,
		},
		{
			name:           "both files",
			manifestFile:   manifestFile,
			legacyLockFile: legacyLockFile,
		},
		{
			name:           "mismatching cluster hashes",
			manifestFile:   manifestFile,
			legacyLockFile: "testdata/lock2.json",
			errorMsg:       "manifest and legacy cluster hashes don't match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Load raw cluster DAG from disk
			dag, err := manifest.LoadDAG(tt.manifestFile, tt.legacyLockFile, nil)
			if tt.errorMsg != "" {
				require.ErrorContains(t, err, tt.errorMsg)
				return
			}
			require.NoError(t, err)

			require.Len(t, dag.GetMutations(), 1) // The only mutation is the `legacy_lock` mutation

			clusterFromDAG, err := manifest.Materialise(dag)
			require.NoError(t, err)

			// Load cluster manifest from disk
			loaded, err := manifest.LoadCluster(tt.manifestFile, tt.legacyLockFile, nil)
			require.NoError(t, err)

			require.True(t, proto.Equal(cluster, loaded))
			require.True(t, proto.Equal(cluster, clusterFromDAG))
		})
	}
}

func testLoadLegacy(t *testing.T, version string) {
	t.Helper()
	n := 4 + rand.Intn(6)
	k := cluster.Threshold(n)

	var opts []func(*cluster.Definition)
	opts = append(opts, cluster.WithVersion(version))
	if version < "v1.5.0" {
		opts = append(opts, cluster.WithLegacyVAddrs(testutil.RandomETHAddress(), testutil.RandomETHAddress()))
	}

	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := cluster.NewForT(t, rand.Intn(10), k, n, seed, random, opts...)

	b, err := json.MarshalIndent(lock, "", "  ")
	require.NoError(t, err)

	file := path.Join(t.TempDir(), "lock.json")

	err = os.WriteFile(file, b, 0o644)
	require.NoError(t, err)

	cluster, err := manifest.LoadCluster("", file, nil)
	require.NoError(t, err)

	require.Equal(t, lock.LockHash, cluster.GetInitialMutationHash())
	require.Equal(t, lock.LockHash, cluster.GetLatestMutationHash())
	require.Equal(t, lock.Name, cluster.GetName())
	require.EqualValues(t, lock.Threshold, cluster.GetThreshold())
	require.Equal(t, lock.DKGAlgorithm, cluster.GetDkgAlgorithm())
	require.Equal(t, lock.ForkVersion, cluster.GetForkVersion())
	require.Equal(t, len(lock.Validators), len(cluster.GetValidators()))
	require.Equal(t, len(lock.Operators), len(cluster.GetOperators()))

	for i, validator := range cluster.GetValidators() {
		require.Equal(t, lock.Validators[i].PubKey, validator.GetPublicKey())
		require.Equal(t, lock.Validators[i].PubShares, validator.GetPubShares())
		require.Equal(t, lock.ValidatorAddresses[i].FeeRecipientAddress, validator.GetFeeRecipientAddress())
		require.Equal(t, lock.ValidatorAddresses[i].WithdrawalAddress, validator.GetWithdrawalAddress())
	}

	for i, operator := range cluster.GetOperators() {
		require.Equal(t, lock.Operators[i].Address, operator.GetAddress())
		require.Equal(t, lock.Operators[i].ENR, operator.GetEnr())
	}
}

// TestLoadModifiedLegacyLock ensure the incorrect hard-coded hash is used for
// legacy locks. This ensures the cluster hash doesn't change even if lock files
// were modified and run with --no-verify.
func TestLoadModifiedLegacyLock(t *testing.T) {
	cluster, err := manifest.LoadCluster("", "testdata/lock3.json", nil)
	require.NoError(t, err)
	hashHex := hex.EncodeToString(cluster.GetInitialMutationHash())
	require.Equal(t, "4073fe542", hashHex[:9])
}
