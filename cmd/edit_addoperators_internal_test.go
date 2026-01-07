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

func TestNewAddOperatorsCmd(t *testing.T) {
	cmd := newAddOperatorsCmd(runAddOperators)
	require.NotNil(t, cmd)
	require.Equal(t, "add-operators", cmd.Use)
	require.Equal(t, "Add new operators to an existing distributed validator cluster", cmd.Short)
	require.Empty(t, cmd.Flags().Args())
}

func TestValidateAddOperatorsConfig(t *testing.T) {
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
		cmdConfig dkg.AddOperatorsConfig
		dkgConfig dkg.Config
		numOps    int
		errMsg    string
	}{
		{
			name:      "output dir is required",
			cmdConfig: dkg.AddOperatorsConfig{},
			errMsg:    "output-dir is required",
		},
		{
			name: "missing new operator enrs",
			cmdConfig: dkg.AddOperatorsConfig{
				OutputDir: ".",
			},
			errMsg: "new-operator-enrs is required",
		},
		{
			name: "lock-file is required",
			cmdConfig: dkg.AddOperatorsConfig{
				OutputDir: ".",
				NewENRs:   []string{"enr:-IS4QH"},
			},
			errMsg: "lock-file does not exist",
		},
		{
			name: "timeout too low",
			cmdConfig: dkg.AddOperatorsConfig{
				OutputDir:      ".",
				LockFilePath:   path.Join(nodeDir(srcDir, 0), clusterLockFile),
				PrivateKeyPath: path.Join(nodeDir(srcDir, 0), enrPrivateKeyFile),
				NewENRs:        []string{"enr:-IS4QH"},
			},
			dkgConfig: dkg.Config{
				Timeout: time.Second,
			},
			errMsg: "timeout must be at least 1 minute",
		},
		{
			name: "duplicate new operator enrs",
			cmdConfig: dkg.AddOperatorsConfig{
				OutputDir:      ".",
				LockFilePath:   path.Join(nodeDir(srcDir, 0), clusterLockFile),
				PrivateKeyPath: path.Join(nodeDir(srcDir, 0), enrPrivateKeyFile),
				NewENRs:        []string{"enr:-IS4QH", "enr:-IS4QH"},
			},
			dkgConfig: dkg.Config{
				Timeout: time.Minute,
			},
			errMsg: "new-operator-enrs contains duplicate ENRs",
		},
		{
			name: "new operator enr matches existing",
			cmdConfig: dkg.AddOperatorsConfig{
				OutputDir:      ".",
				LockFilePath:   path.Join(nodeDir(srcDir, 0), clusterLockFile),
				PrivateKeyPath: path.Join(nodeDir(srcDir, 0), enrPrivateKeyFile),
				NewENRs:        []string{lock.Operators[0].ENR},
			},
			dkgConfig: dkg.Config{
				Timeout: time.Minute,
			},
			errMsg: "new-operator-enrs contains an existing operator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAddOperatorsConfig(t.Context(), &tt.cmdConfig, &tt.dkgConfig)
			if tt.errMsg != "" {
				require.Equal(t, tt.errMsg, err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
