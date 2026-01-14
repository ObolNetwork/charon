// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

func TestNewRecreatePrivateKeysCmd(t *testing.T) {
	cmd := newRecreatePrivateKeysCmd(runRecreatePrivateKeys)
	require.NotNil(t, cmd)
	require.Equal(t, "recreate-private-keys", cmd.Use)
	require.Equal(t, "Create new private key shares to replace existing validator private key shares", cmd.Short)
	require.Empty(t, cmd.Flags().Args())
}

func TestValidateReshareConfig(t *testing.T) {
	realDir := t.TempDir()
	err := os.WriteFile(filepath.Join(realDir, clusterLockFile), []byte("{}"), 0o444)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(realDir, enrPrivateKeyFile), []byte("{}"), 0o444)
	require.NoError(t, err)

	validatorKeysDir := filepath.Join(realDir, validatorKeysSubDir)
	err = app.CreateNewEmptyDir(validatorKeysDir)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(validatorKeysDir, "keystore-0.json"), []byte("{}"), 0o444)
	require.NoError(t, err)

	tests := []struct {
		name   string
		config dkg.ReshareConfig
		numOps int
		errMsg string
	}{
		{
			name:   "output dir is required",
			config: dkg.ReshareConfig{},
			errMsg: "output-dir is required",
		},
		{
			name:   "lock-file is required",
			config: dkg.ReshareConfig{OutputDir: "."},
			errMsg: "lock-file is required",
		},
		{
			name: "private-key-file is required",
			config: dkg.ReshareConfig{
				OutputDir:    ".",
				LockFilePath: filepath.Join(realDir, clusterLockFile),
			},
			errMsg: "private-key-file is required",
		},
		{
			name: "timeout too low",
			config: dkg.ReshareConfig{
				OutputDir:        ".",
				LockFilePath:     filepath.Join(realDir, clusterLockFile),
				PrivateKeyPath:   filepath.Join(realDir, enrPrivateKeyFile),
				ValidatorKeysDir: validatorKeysDir,
				DKGConfig: dkg.Config{
					Timeout: time.Second,
				},
			},
			errMsg: "timeout must be at least 1 minute",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateReshareConfig(tt.config)
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
		err = os.WriteFile(filepath.Join(srcDir, enrPrivateKeyFile), []byte("{}"), 0o444)
		require.NoError(t, err)

		config := dkg.ReshareConfig{
			OutputDir:      ".",
			LockFilePath:   filepath.Join(srcDir, clusterLockFile),
			PrivateKeyPath: filepath.Join(srcDir, enrPrivateKeyFile),
			DKGConfig: dkg.Config{
				Timeout: time.Minute,
			},
		}

		err = validateReshareConfig(config)
		require.Equal(t, "validator-keys-dir is required", err.Error())

		validatorKeysDir := filepath.Join(srcDir, validatorKeysSubDir)
		err = app.CreateNewEmptyDir(validatorKeysDir)
		require.NoError(t, err)

		config.ValidatorKeysDir = validatorKeysDir
		err = validateReshareConfig(config)
		require.Equal(t, "validator-keys-dir empty", err.Error())
	})
}
