// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/eth2util"
)

func TestNewReplaceOperatorCmd(t *testing.T) {
	cmd := newReplaceOperatorCmd(runReplaceOperator)
	require.NotNil(t, cmd)
	require.Equal(t, "replace-operator", cmd.Use)
	require.Equal(t, "Replace an operator in an existing distributed validator cluster", cmd.Short)
	require.Empty(t, cmd.Flags().Args())
}

func TestValidateReplaceOperatorConfig(t *testing.T) {
	srcDir := t.TempDir()
	conf := clusterConfig{
		ClusterDir:        srcDir,
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

	err := runCreateCluster(t.Context(), &buf, conf)
	require.NoError(t, err)

	lock, err := dkg.LoadAndVerifyClusterLock(t.Context(), path.Join(nodeDir(srcDir, 0), clusterLockFile), "", true)
	require.NoError(t, err)

	tests := []struct {
		name      string
		cmdConfig dkg.ReplaceOperatorConfig
		dkgConfig dkg.Config
		errMsg    string
	}{
		{
			name:      "output dir is required",
			cmdConfig: dkg.ReplaceOperatorConfig{},
			errMsg:    "output-dir is required",
		},
		{
			name: "new operator enr is required",
			cmdConfig: dkg.ReplaceOperatorConfig{
				OutputDir: ".",
			},
			errMsg: "new-operator-enr is required",
		},
		{
			name: "old operator enr is required",
			cmdConfig: dkg.ReplaceOperatorConfig{
				OutputDir: ".",
				NewENR:    "enr:-IS4QH",
			},
			errMsg: "old-operator-enr is required",
		},
		{
			name: "old and new operator enr cannot be the same",
			cmdConfig: dkg.ReplaceOperatorConfig{
				OutputDir: ".",
				NewENR:    "enr:-IS4QH",
				OldENR:    "enr:-IS4QH",
			},
			errMsg: "old-operator-enr and new-operator-enr cannot be the same",
		},
		{
			name: "lock-file does not exist",
			cmdConfig: dkg.ReplaceOperatorConfig{
				OutputDir: ".",
				NewENR:    "enr:-IS4QH",
				OldENR:    "enr:-IS4QJ",
			},
			errMsg: "lock-file does not exist",
		},
		{
			name: "timeout too low",
			cmdConfig: dkg.ReplaceOperatorConfig{
				OutputDir:      ".",
				LockFilePath:   path.Join(nodeDir(srcDir, 0), clusterLockFile),
				PrivateKeyPath: path.Join(nodeDir(srcDir, 0), enrPrivateKeyFile),
				NewENR:         "enr:-IS4QH",
				OldENR:         lock.Operators[1].ENR,
			},
			dkgConfig: dkg.Config{
				Timeout: time.Second,
			},
			errMsg: "timeout must be at least 1 minute",
		},
		{
			name: "old operator enr shall not participate in the ceremony",
			cmdConfig: dkg.ReplaceOperatorConfig{
				OutputDir:      ".",
				LockFilePath:   path.Join(nodeDir(srcDir, 0), clusterLockFile),
				PrivateKeyPath: path.Join(nodeDir(srcDir, 0), enrPrivateKeyFile),
				NewENR:         "enr:-IS4QH",
				OldENR:         lock.Operators[0].ENR,
			},
			dkgConfig: dkg.Config{
				Timeout: time.Minute,
			},
			errMsg: "the old-operator-enr shall not participate in the ceremony",
		},
		{
			name: "new operator enr matches existing",
			cmdConfig: dkg.ReplaceOperatorConfig{
				OutputDir:      ".",
				LockFilePath:   path.Join(nodeDir(srcDir, 0), clusterLockFile),
				PrivateKeyPath: path.Join(nodeDir(srcDir, 0), enrPrivateKeyFile),
				NewENR:         lock.Operators[1].ENR,
				OldENR:         lock.Operators[2].ENR,
			},
			dkgConfig: dkg.Config{
				Timeout: time.Minute,
			},
			errMsg: "new-operator-enr matches an existing operator",
		},
		{
			name: "old operator enr does not match any existing operator",
			cmdConfig: dkg.ReplaceOperatorConfig{
				OutputDir:      ".",
				LockFilePath:   path.Join(nodeDir(srcDir, 0), clusterLockFile),
				PrivateKeyPath: path.Join(nodeDir(srcDir, 0), enrPrivateKeyFile),
				NewENR:         "enr:-IS4QH",
				OldENR:         "enr:-IS4QJ",
			},
			dkgConfig: dkg.Config{
				Timeout: time.Minute,
			},
			errMsg: "old-operator-enr does not match any existing operator in the cluster lock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateReplaceOperatorConfig(t.Context(), &tt.cmdConfig, &tt.dkgConfig)
			if tt.errMsg != "" {
				require.Equal(t, tt.errMsg, err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
