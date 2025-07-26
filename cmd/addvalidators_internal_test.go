// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg"
)

func TestValidateConfigAddValidators(t *testing.T) {
	realDir := t.TempDir()
	err := os.WriteFile(filepath.Join(realDir, clusterLockFile), []byte("{}"), 0o444)
	require.NoError(t, err)

	tests := []struct {
		name   string
		conf   addValidatorsConfig
		numOps int
		errMsg string
	}{
		{
			name: "insufficient validators",
			conf: addValidatorsConfig{
				NumValidators: 0,
			},
			errMsg: "num-validators must be greater than 0",
		},
		{
			name: "dst dir is required",
			conf: addValidatorsConfig{
				DstDir:        "",
				NumValidators: 1,
			},
			errMsg: "dst-dir is required",
		},
		{
			name: "src dir is required",
			conf: addValidatorsConfig{
				DstDir:        ".",
				SrcDir:        "",
				NumValidators: 1,
			},
			errMsg: "src-dir is required",
		},
		{
			name: "missing lock file",
			conf: addValidatorsConfig{
				SrcDir:        ".",
				DstDir:        ".",
				NumValidators: 1,
			},
			errMsg: "src-dir must contain a cluster-lock.json file",
		},
		{
			name: "addrs length mismatch",
			conf: addValidatorsConfig{
				SrcDir:            realDir,
				DstDir:            ".",
				NumValidators:     1,
				WithdrawalAddrs:   []string{feeRecipientAddr, feeRecipientAddr},
				FeeRecipientAddrs: []string{feeRecipientAddr},
			},
			errMsg: "mismatching --num-validators and --withdrawal-addresses",
		},
		{
			name: "single addr for all validators",
			conf: addValidatorsConfig{
				SrcDir:            realDir,
				DstDir:            ".",
				NumValidators:     2,
				WithdrawalAddrs:   []string{feeRecipientAddr},
				FeeRecipientAddrs: []string{feeRecipientAddr},
			},
		},
		{
			name: "count and addrs mismatch",
			conf: addValidatorsConfig{
				SrcDir:            realDir,
				DstDir:            ".",
				NumValidators:     2,
				WithdrawalAddrs:   []string{feeRecipientAddr, feeRecipientAddr, feeRecipientAddr},
				FeeRecipientAddrs: []string{feeRecipientAddr, feeRecipientAddr, feeRecipientAddr},
			},
			errMsg: "mismatching --num-validators and --fee-recipient-addresses",
		},
		{
			name: "multiple addrs for multiple validators",
			conf: addValidatorsConfig{
				SrcDir:            realDir,
				DstDir:            ".",
				NumValidators:     2,
				WithdrawalAddrs:   []string{feeRecipientAddr, feeRecipientAddr},
				FeeRecipientAddrs: []string{feeRecipientAddr, feeRecipientAddr},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(&tt.conf)
			if tt.errMsg != "" {
				require.Equal(t, tt.errMsg, err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCreateDstClusterDir(t *testing.T) {
	tmpDir := t.TempDir()

	err := createDstClusterDir(tmpDir)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(tmpDir, clusterLockFile), []byte("{}"), 0o444)
	require.NoError(t, err)

	err = createDstClusterDir(tmpDir)
	require.ErrorContains(t, err, "directory not empty")
}

func TestVerifyLock(t *testing.T) {
	b, err := os.ReadFile("testdata/test_cluster_lock.json")
	require.NoError(t, err)

	var lock cluster.Lock

	err = json.Unmarshal(b, &lock)
	require.NoError(t, err)

	err = verifyLock(t.Context(), lock, dkg.Config{NoVerify: true})
	require.NoError(t, err)

	err = verifyLock(t.Context(), lock, dkg.Config{NoVerify: false})
	require.NoError(t, err)
}
