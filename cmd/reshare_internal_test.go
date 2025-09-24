// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/dkg"
)

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
		{
			name:      "timeout too low",
			outputDir: ".",
			config: dkg.Config{
				DataDir: realDir,
				Timeout: time.Second,
			},
			errMsg: "timeout must be at least 1 minute",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateReshareConfig(tt.outputDir, tt.config)
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

		err = validateReshareConfig(outputDir, config)
		require.Equal(t, "data-dir must contain a non-empty validator_keys directory", err.Error())

		validatorKeysDir := filepath.Join(srcDir, validatorKeysSubDir)
		err = app.CreateNewEmptyDir(validatorKeysDir)
		require.NoError(t, err)

		err = validateReshareConfig(outputDir, config)
		require.Equal(t, "data-dir must contain a non-empty validator_keys directory", err.Error())
	})
}
