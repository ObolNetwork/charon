// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/p2p"
)

func TestNewAddOperatorsCmd(t *testing.T) {
	cmd := newAddOperatorsCmd(runAddOperators)
	require.NotNil(t, cmd)
	require.Equal(t, "add-operators", cmd.Use)
	require.Equal(t, "Add new operators to an existing distributed validator cluster", cmd.Short)
	require.Empty(t, cmd.Flags().Args())
}

func TestValidateAddOperatorsConfig(t *testing.T) {
	realDir := t.TempDir()
	lock := mustLoadTestLockFile(t, "testdata/test_cluster_lock.json")
	lockBytes, err := lock.MarshalJSON()
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(realDir, clusterLockFile), lockBytes, 0o444)
	require.NoError(t, err)
	_, err = p2p.NewSavedPrivKey(realDir)
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
		{
			name: "timeout too low",
			cmdConfig: dkg.AddOperatorsConfig{
				OutputDir: ".",
				NewENRs:   []string{"enr:-IS4QH"},
			},
			dkgConfig: dkg.Config{
				DataDir: realDir,
				Timeout: time.Second,
			},
			errMsg: "timeout must be at least 1 minute",
		},
		{
			name: "new operator enr matches existing",
			cmdConfig: dkg.AddOperatorsConfig{
				OutputDir: ".",
				NewENRs:   []string{lock.Operators[0].ENR},
			},
			dkgConfig: dkg.Config{
				DataDir: realDir,
				Timeout: time.Minute,
			},
			errMsg: "new-operator-enrs contains an existing operator",
		},
		{
			name: "duplicate new operator enrs",
			cmdConfig: dkg.AddOperatorsConfig{
				OutputDir: ".",
				NewENRs:   []string{"enr:-IS4QH", "enr:-IS4QH"},
			},
			dkgConfig: dkg.Config{
				DataDir: realDir,
				Timeout: time.Minute,
			},
			errMsg: "new-operator-enrs contains duplicate ENRs",
		},
		{
			name: "new threshold too low",
			cmdConfig: dkg.AddOperatorsConfig{
				OutputDir:    ".",
				NewENRs:      []string{"enr:-IS4QH"},
				NewThreshold: 1,
			},
			dkgConfig: dkg.Config{
				DataDir: realDir,
				Timeout: time.Minute,
			},
			errMsg: "new-threshold is invalid",
		},
		{
			name: "new threshold too high",
			cmdConfig: dkg.AddOperatorsConfig{
				OutputDir:    ".",
				NewENRs:      []string{"enr:-IS4QH"},
				NewThreshold: 10,
			},
			dkgConfig: dkg.Config{
				DataDir: realDir,
				Timeout: time.Minute,
			},
			errMsg: "new-threshold is invalid",
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
