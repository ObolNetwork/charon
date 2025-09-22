// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/relay"
)

func TestRunAddOperators(t *testing.T) {
	const (
		oldN    = 4
		newN    = 7
		oldT    = 3
		numVals = 3
	)

	clusterDir := t.TempDir()

	// This test creates a solo cluster 4/3, then add-operators adds 3 new operators.
	conf := clusterConfig{
		ClusterDir:        clusterDir,
		Name:              "test_cluster",
		NumNodes:          oldN,
		Threshold:         oldT,
		NumDVs:            numVals,
		Network:           eth2util.Holesky.Name,
		TargetGasLimit:    36000000,
		FeeRecipientAddrs: []string{feeRecipientAddr, feeRecipientAddr, feeRecipientAddr},
		WithdrawalAddrs:   []string{feeRecipientAddr, feeRecipientAddr, feeRecipientAddr},
	}

	var buf bytes.Buffer

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	err := runCreateCluster(ctx, &buf, conf)
	require.NoError(t, err)

	entries, err := os.ReadDir(conf.ClusterDir)
	require.NoError(t, err)
	require.Len(t, entries, oldN)

	// Creating new nodes with just ENRs and lock files.
	newENRs := make([]string, newN-oldN)
	for i := conf.NumNodes; i < newN; i++ {
		ndir := nodeDir(conf.ClusterDir, i)
		require.NoError(t, os.MkdirAll(ndir, 0o755))

		err := runCreateEnrCmd(io.Discard, ndir)
		require.NoError(t, err)

		key, err := p2p.LoadPrivKey(ndir)
		require.NoError(t, err)

		er, err := enr.New(key)
		require.NoError(t, err)

		newENRs[i-oldN] = er.String()

		srcLockPath := filepath.Join(nodeDir(conf.ClusterDir, 0), clusterLockFile)
		err = app.CopyFile(srcLockPath, filepath.Join(ndir, clusterLockFile))
		require.NoError(t, err)
	}

	dstDir := t.TempDir()
	relayAddr := relay.StartRelay(ctx, t)

	var (
		eg       errgroup.Group
		nodeDirs []string
	)

	for i := range newN {
		config := dkg.AddOperatorsConfig{
			OutputDir: nodeDir(dstDir, i),
			NewENRs:   newENRs,
		}
		dkgConfig := dkg.Config{
			DataDir: nodeDir(conf.ClusterDir, i),
			P2P: p2p.Config{
				Relays:   []string{relayAddr},
				TCPAddrs: []string{testutil.AvailableAddr(t).String()},
			},
			Log:           log.DefaultConfig(),
			ShutdownDelay: time.Second,
			Timeout:       30 * time.Second,
			NoVerify:      true,
		}

		nodeDirs = append(nodeDirs, config.OutputDir)

		eg.Go(func() error {
			peerCtx := log.WithCtx(ctx, z.Int("peer_index", i))
			return runAddOperators(peerCtx, config, dkgConfig)
		})
	}

	err = eg.Wait()
	testutil.SkipIfBindErr(t, err)
	testutil.RequireNoError(t, err)

	verifyClusterValidators(t, numVals, nodeDirs)
}

func TestNewAddOperatorsCmd(t *testing.T) {
	cmd := newAddOperatorsCmd(runAddOperators)
	require.NotNil(t, cmd)
	require.Equal(t, "add-operators", cmd.Use)
	require.Equal(t, "Add new operators to an existing distributed validator cluster", cmd.Short)
	require.Empty(t, cmd.Flags().Args())
}

func TestValidateAddOperatorsConfig(t *testing.T) {
	realDir := t.TempDir()
	err := os.WriteFile(filepath.Join(realDir, clusterLockFile), []byte("{}"), 0o444)
	require.NoError(t, err)

	tests := []struct {
		name      string
		cmdConfig dkg.AddOperatorsConfig
		dkgConfig dkg.Config
		numOps    int
		errMsg    string
	}{
		{
			name: "missing new operator enrs",
			cmdConfig: dkg.AddOperatorsConfig{
				OutputDir: ".",
			},
			errMsg: "new-operator-enrs is required",
		},
		{
			name: "output dir is required",
			cmdConfig: dkg.AddOperatorsConfig{
				OutputDir: "",
				NewENRs:   []string{"enr:-IS4QH"},
			},
			errMsg: "output-dir is required",
		},
		{
			name: "data dir is required",
			cmdConfig: dkg.AddOperatorsConfig{
				OutputDir: ".",
				NewENRs:   []string{"enr:-IS4QH"},
			},
			errMsg: "data-dir is required",
		},
		{
			name: "missing lock file",
			cmdConfig: dkg.AddOperatorsConfig{
				OutputDir: ".",
				NewENRs:   []string{"enr:-IS4QH"},
			},
			dkgConfig: dkg.Config{
				DataDir: ".",
			},
			errMsg: "data-dir must contain a cluster-lock.json file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAddOperatorsConfig(&tt.cmdConfig, &tt.dkgConfig)
			if tt.errMsg != "" {
				require.Equal(t, tt.errMsg, err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func verifyClusterValidators(t *testing.T, numVals int, nodeDirs []string) {
	t.Helper()

	numNodes := len(nodeDirs)
	clusterSecrets := make([][]tbls.PrivateKey, numNodes)

	for i := range numNodes {
		ndir := nodeDirs[i]
		lock, err := loadLockJSON(t.Context(), ndir, dkg.Config{})
		require.NoError(t, err)
		require.Len(t, lock.Operators, numNodes)
		require.Len(t, lock.Validators, numVals)

		keystoreDir := filepath.Join(ndir, validatorKeysSubDir)
		require.True(t, app.FileExists(keystoreDir))

		kf, err := keystore.LoadFilesUnordered(keystoreDir)
		require.NoError(t, err)
		require.Len(t, kf, numVals)

		secrets, err := kf.SequencedKeys()
		require.NoError(t, err)
		require.Len(t, secrets, numVals)

		clusterSecrets[i] = secrets
	}

	data := []byte("test data")
	allSigs := make([][]tbls.Signature, numVals)
	clusterPubKeys := make([][]tbls.PublicKey, numVals)

	for valIdx := range numVals {
		sigs := make([]tbls.Signature, numNodes)

		for nodeIdx := range numNodes {
			sig, err := tbls.Sign(clusterSecrets[nodeIdx][valIdx], data)
			require.NoError(t, err)

			sigs[nodeIdx] = sig
		}

		allSigs[valIdx] = sigs
		clusterPubKeys[valIdx] = make([]tbls.PublicKey, numNodes)

		for nodeIdx := range numNodes {
			pubKey, err := tbls.SecretToPublicKey(clusterSecrets[nodeIdx][valIdx])
			require.NoError(t, err)

			clusterPubKeys[valIdx][nodeIdx] = pubKey
		}
	}

	for valIdx := range numVals {
		aSig, err := tbls.Aggregate(allSigs[valIdx])
		require.NoError(t, err)

		err = tbls.VerifyAggregate(clusterPubKeys[valIdx], aSig, data)
		require.NoError(t, err)
	}
}
