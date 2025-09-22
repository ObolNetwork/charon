// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"context"
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
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/relay"
)

func TestRunReshare(t *testing.T) {
	// This test creates a solo cluster with all charon data for all nodes.
	// Then it runs reshare on each node in parallel.
	conf := clusterConfig{
		ClusterDir:        t.TempDir(),
		Name:              t.Name(),
		NumNodes:          4,
		Threshold:         3,
		NumDVs:            3,
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
	require.Len(t, entries, 4)

	dstDir := t.TempDir()
	relayAddr := relay.StartRelay(ctx, t)

	var (
		eg       errgroup.Group
		nodeDirs []string
	)

	for i := 0; i < conf.NumNodes; i++ {
		outputDir := nodeDir(dstDir, i)
		config := dkg.Config{
			DataDir: nodeDir(conf.ClusterDir, i),
			P2P: p2p.Config{
				Relays:   []string{relayAddr},
				TCPAddrs: []string{testutil.AvailableAddr(t).String()},
			},
			Log:           log.DefaultConfig(),
			ShutdownDelay: time.Second,
			Timeout:       time.Minute,
			NoVerify:      true,
		}

		nodeDirs = append(nodeDirs, outputDir)

		eg.Go(func() error {
			peerCtx := log.WithCtx(ctx, z.Int("peer_index", i))
			return runReshare(peerCtx, outputDir, config)
		})
	}

	err = eg.Wait()
	testutil.SkipIfBindErr(t, err)
	testutil.RequireNoError(t, err)

	verifyClusterValidators(t, conf.NumDVs, nodeDirs)
}

func TestNewReshareCmd(t *testing.T) {
	cmd := newReshareCmd(runReshare)
	require.NotNil(t, cmd)
	require.Equal(t, "reshare", cmd.Use)
	require.Equal(t, "Reshare existing validator keys", cmd.Short)
	require.Empty(t, cmd.Flags().Args())
}

func TestValidateReshareConfig(t *testing.T) {
	realDir := t.TempDir()
	err := os.WriteFile(filepath.Join(realDir, clusterLockFile), []byte("{}"), 0o444)
	require.NoError(t, err)

	validatorKeysDir := filepath.Join(realDir, validatorKeysSubDir)
	err = app.CreateNewEmptyDir(validatorKeysDir)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(validatorKeysDir, "keystore-0.json"), []byte("{}"), 0o444)
	require.NoError(t, err)

	tests := []struct {
		name      string
		outputDir string
		config    dkg.Config
		numOps    int
		errMsg    string
	}{
		{
			name:      "output dir is required",
			outputDir: "",
			config:    dkg.Config{},
			errMsg:    "output-dir is required",
		},
		{
			name:      "data dir is required",
			outputDir: ".",
			config: dkg.Config{
				DataDir: "",
			},
			errMsg: "data-dir is required",
		},
		{
			name:      "missing lock file",
			outputDir: ".",
			config: dkg.Config{
				DataDir: ".",
			},
			errMsg: "data-dir must contain a cluster-lock.json file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateReshareConfig(t.Context(), tt.outputDir, tt.config)
			if tt.errMsg != "" {
				require.Equal(t, tt.errMsg, err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}

	t.Run("empty validator_keys dir", func(t *testing.T) {
		srcDir := t.TempDir()
		err := os.WriteFile(filepath.Join(srcDir, clusterLockFile), []byte("{}"), 0o444)
		require.NoError(t, err)

		outputDir := "."
		config := dkg.Config{
			DataDir: srcDir,
		}

		err = validateReshareConfig(t.Context(), outputDir, config)
		require.Equal(t, "data-dir must contain a non-empty validator_keys directory", err.Error())

		validatorKeysDir := filepath.Join(srcDir, validatorKeysSubDir)
		err = app.CreateNewEmptyDir(validatorKeysDir)
		require.NoError(t, err)

		err = validateReshareConfig(t.Context(), outputDir, config)
		require.Equal(t, "data-dir must contain a non-empty validator_keys directory", err.Error())
	})
}
