// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/dkg"
)

func TestNewRemoveOperatorsCmd(t *testing.T) {
	cmd := newRemoveOperatorsCmd(runRemoveOperators)
	require.NotNil(t, cmd)
	require.Equal(t, "remove-operators", cmd.Use)
	require.Equal(t, "Remove operators from an existing distributed validator cluster", cmd.Short)
	require.Empty(t, cmd.Flags().Args())
}

func TestValidateRemoveOperatorsConfig(t *testing.T) {
	realDir := t.TempDir()
	err := os.WriteFile(filepath.Join(realDir, clusterLockFile), []byte("{}"), 0o444)
	require.NoError(t, err)

	tests := []struct {
		name      string
		cmdConfig dkg.RemoveOperatorsConfig
		dkgConfig dkg.Config
		numOps    int
		errMsg    string
	}{
		{
			name: "missing old operator enrs",
			cmdConfig: dkg.RemoveOperatorsConfig{
				OutputDir: ".",
			},
			errMsg: "old-operator-enrs is required",
		},
		{
			name: "data dir is required",
			cmdConfig: dkg.RemoveOperatorsConfig{
				OutputDir: ".",
				OldENRs:   []string{"enr:-IS4QH"},
			},
			errMsg: "data-dir is required",
		},
		{
			name: "missing lock file",
			cmdConfig: dkg.RemoveOperatorsConfig{
				OutputDir: ".",
				OldENRs:   []string{"enr:-IS4QH"},
			},
			dkgConfig: dkg.Config{
				DataDir: ".",
			},
			errMsg: "data-dir must contain a cluster-lock.json file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRemoveOperatorsConfig(&tt.cmdConfig, &tt.dkgConfig)
			if tt.errMsg != "" {
				require.Equal(t, tt.errMsg, err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
