// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

func TestNewRemoveOperatorsCmd(t *testing.T) {
	cmd := newRemoveOperatorsCmd(runRemoveOperators)
	require.NotNil(t, cmd)
	require.Equal(t, "remove-operators", cmd.Use)
	require.Equal(t, "Remove operators from an existing distributed validator cluster", cmd.Short)
	require.Empty(t, cmd.Flags().Args())
}

func TestValidateRemoveOperatorsConfig(t *testing.T) {
	srcDir := t.TempDir()
	conf := clusterConfig{
		ClusterDir:        srcDir,
		Name:              t.Name(),
		NumNodes:          7,
		Threshold:         5,
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
		cmdConfig dkg.RemoveOperatorsConfig
		dkgConfig dkg.Config
		numOps    int
		errMsg    string
	}{
		{
			name: "operator-enrs-to-remove is required",
			cmdConfig: dkg.RemoveOperatorsConfig{
				OutputDir: ".",
			},
			errMsg: "operator-enrs-to-remove is required",
		},
		{
			name: "lock-file does not exist",
			cmdConfig: dkg.RemoveOperatorsConfig{
				OutputDir:    ".",
				RemovingENRs: []string{"enr:-IS4QH"},
			},
			errMsg: "lock-file does not exist",
		},
		{
			name: "timeout too low",
			cmdConfig: dkg.RemoveOperatorsConfig{
				OutputDir:      ".",
				LockFilePath:   path.Join(nodeDir(srcDir, 0), clusterLockFile),
				PrivateKeyPath: path.Join(nodeDir(srcDir, 0), enrPrivateKeyFile),
				RemovingENRs:   []string{"enr:-IS4QH"},
			},
			dkgConfig: dkg.Config{
				Timeout: time.Second,
			},
			errMsg: "timeout must be at least 1 minute",
		},
		{
			name: "old operator enr does not exist",
			cmdConfig: dkg.RemoveOperatorsConfig{
				OutputDir:      ".",
				LockFilePath:   path.Join(nodeDir(srcDir, 0), clusterLockFile),
				PrivateKeyPath: path.Join(nodeDir(srcDir, 0), enrPrivateKeyFile),
				RemovingENRs:   []string{"enr:-IS4QH"},
			},
			dkgConfig: dkg.Config{
				Timeout: time.Minute,
			},
			errMsg: "operator-enrs-to-remove contains a non-existing operator",
		},
		{
			name: "participating operator enr does not exist",
			cmdConfig: dkg.RemoveOperatorsConfig{
				OutputDir:         ".",
				LockFilePath:      path.Join(nodeDir(srcDir, 0), clusterLockFile),
				PrivateKeyPath:    path.Join(nodeDir(srcDir, 0), enrPrivateKeyFile),
				RemovingENRs:      []string{lock.Operators[0].ENR},
				ParticipatingENRs: []string{"enr:-IS4QH"},
			},
			dkgConfig: dkg.Config{
				Timeout: time.Minute,
			},
			errMsg: "participating-operator-enrs contains a non-existing operator",
		},
		{
			name: "new threshold too low",
			cmdConfig: dkg.RemoveOperatorsConfig{
				OutputDir:      ".",
				LockFilePath:   path.Join(nodeDir(srcDir, 0), clusterLockFile),
				PrivateKeyPath: path.Join(nodeDir(srcDir, 0), enrPrivateKeyFile),
				RemovingENRs:   []string{lock.Operators[1].ENR},
				NewThreshold:   1,
			},
			dkgConfig: dkg.Config{
				Timeout: time.Minute,
			},
			errMsg: "new-threshold is invalid",
		},
		{
			name: "new threshold too high",
			cmdConfig: dkg.RemoveOperatorsConfig{
				OutputDir:      ".",
				LockFilePath:   path.Join(nodeDir(srcDir, 0), clusterLockFile),
				PrivateKeyPath: path.Join(nodeDir(srcDir, 0), enrPrivateKeyFile),
				RemovingENRs:   []string{lock.Operators[1].ENR},
				NewThreshold:   10,
			},
			dkgConfig: dkg.Config{
				Timeout: time.Minute,
			},
			errMsg: "new-threshold is invalid",
		},
		{
			name: "missing validator_keys",
			cmdConfig: dkg.RemoveOperatorsConfig{
				OutputDir:      ".",
				LockFilePath:   path.Join(nodeDir(srcDir, 0), clusterLockFile),
				PrivateKeyPath: path.Join(nodeDir(srcDir, 0), enrPrivateKeyFile),
				RemovingENRs:   []string{lock.Operators[1].ENR},
			},
			dkgConfig: dkg.Config{
				Timeout: time.Minute,
			},
			errMsg: "load private key share: no keys found",
		},
		{
			name: "old operator enrs contains duplicate",
			cmdConfig: dkg.RemoveOperatorsConfig{
				OutputDir:      ".",
				LockFilePath:   path.Join(nodeDir(srcDir, 0), clusterLockFile),
				PrivateKeyPath: path.Join(nodeDir(srcDir, 0), enrPrivateKeyFile),
				RemovingENRs:   []string{lock.Operators[0].ENR, lock.Operators[0].ENR},
			},
			dkgConfig: dkg.Config{
				Timeout: time.Minute,
			},
			errMsg: "operator-enrs-to-remove contains duplicate ENRs",
		},
		{
			name: "participating operator enrs contains duplicate",
			cmdConfig: dkg.RemoveOperatorsConfig{
				OutputDir:         ".",
				LockFilePath:      path.Join(nodeDir(srcDir, 0), clusterLockFile),
				PrivateKeyPath:    path.Join(nodeDir(srcDir, 0), enrPrivateKeyFile),
				RemovingENRs:      []string{lock.Operators[0].ENR},
				ParticipatingENRs: []string{lock.Operators[0].ENR, lock.Operators[0].ENR},
			},
			dkgConfig: dkg.Config{
				Timeout: time.Minute,
			},
			errMsg: "participating-operator-enrs contains duplicate ENRs",
		},
		{
			name: "participating-operator-enrs is required",
			cmdConfig: dkg.RemoveOperatorsConfig{
				OutputDir:      ".",
				LockFilePath:   path.Join(nodeDir(srcDir, 0), clusterLockFile),
				PrivateKeyPath: path.Join(nodeDir(srcDir, 0), enrPrivateKeyFile),
				RemovingENRs:   []string{lock.Operators[0].ENR, lock.Operators[1].ENR, lock.Operators[2].ENR},
			},
			dkgConfig: dkg.Config{
				Timeout: time.Minute,
			},
			errMsg: "participating-operator-enrs is required when after the removal, the remaining amount of operators is below the current threshold",
		},
		{
			name: "not enough participating operators",
			cmdConfig: dkg.RemoveOperatorsConfig{
				OutputDir:         ".",
				LockFilePath:      path.Join(nodeDir(srcDir, 0), clusterLockFile),
				PrivateKeyPath:    path.Join(nodeDir(srcDir, 0), enrPrivateKeyFile),
				RemovingENRs:      []string{lock.Operators[0].ENR, lock.Operators[1].ENR, lock.Operators[2].ENR},
				ParticipatingENRs: []string{lock.Operators[0].ENR, lock.Operators[1].ENR},
			},
			dkgConfig: dkg.Config{
				Timeout: time.Minute,
			},
			errMsg: "not enough participating operators to complete the protocol, need at least threshold participants",
		},
		{
			name: "removed participant",
			cmdConfig: dkg.RemoveOperatorsConfig{
				OutputDir:      ".",
				LockFilePath:   path.Join(nodeDir(srcDir, 0), clusterLockFile),
				PrivateKeyPath: path.Join(nodeDir(srcDir, 0), enrPrivateKeyFile),
				RemovingENRs:   []string{lock.Operators[0].ENR, lock.Operators[1].ENR},
			},
			dkgConfig: dkg.Config{
				Timeout: time.Minute,
			},
			errMsg: "enrs being removed cannot participate unless specified in participating-operator-enrs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRemoveOperatorsConfig(t.Context(), &tt.cmdConfig, &tt.dkgConfig)
			if tt.errMsg != "" {
				require.Equal(t, tt.errMsg, err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
