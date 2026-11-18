// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/obolnetwork/charon/app/eth1wrap/mocks"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
)

func TestLoadDefinition(t *testing.T) {
	tmp := t.TempDir()

	// Valid definition
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := cluster.NewForT(t, 1, 2, 3, seed, random)
	validDef := lock.Definition
	validFile := path.Join(tmp, "valid-cluster-definition.json")
	b, err := json.MarshalIndent(validDef, "", " ")
	require.NoError(t, err)
	err = os.WriteFile(validFile, b, 0o666)
	require.NoError(t, err)

	// Invalid definition
	invalidDef := cluster.Definition{}
	invalidFile := path.Join(tmp, "invalid-cluster-definition.json")
	err = os.WriteFile(invalidFile, []byte{1, 2, 3}, 0o666)
	require.NoError(t, err)

	// Invalid definition without definition_hash and config_hash
	invalidFile2 := path.Join(tmp, "invalid-cluster-definition2.json")

	var rawJSONString map[string]any
	require.NoError(t, json.Unmarshal(b, &rawJSONString))

	delete(rawJSONString, "config_hash")
	delete(rawJSONString, "definition_hash")

	b2, err := json.Marshal(rawJSONString)
	require.NoError(t, err)

	err = os.WriteFile(invalidFile2, b2, 0o666)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, os.Remove(validFile))
		require.NoError(t, os.Remove(invalidFile))
		require.NoError(t, os.Remove(invalidFile2))
	}()

	tests := []struct {
		name     string
		defFile  string
		want     cluster.Definition
		noVerify bool
		wantErr  bool
	}{
		{
			name:     "Load valid definition",
			defFile:  validFile,
			want:     validDef,
			noVerify: false,
			wantErr:  false,
		},
		{
			name:     "Definition file doesn't exist",
			defFile:  "",
			want:     invalidDef,
			noVerify: false,
			wantErr:  true,
		},
		{
			name:     "Load invalid definition",
			defFile:  invalidFile,
			want:     invalidDef,
			noVerify: false,
			wantErr:  true,
		},
		{
			name:     "Load invalid definition with no verify",
			defFile:  invalidFile2,
			want:     validDef,
			noVerify: true,
			wantErr:  false,
		},
		{
			name:     "Load invalid definition without no verify",
			defFile:  invalidFile2,
			noVerify: false,
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eth1Cl := mocks.NewEthClientRunner(t)
			// Maybe is used because we're not testing this function however it may be called when first signature check fails therefore return false
			eth1Cl.On("VerifySmartContractBasedSignature", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()

			got, err := loadDefinition(context.Background(), Config{DefFile: tt.defFile, NoVerify: tt.noVerify}, eth1Cl)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			got, err = got.SetDefinitionHashes()
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestCheckClearDataDir(t *testing.T) {
	tests := []struct {
		name       string
		prepare    func(rootDir string, dataDir string)
		checkError func(err error)
	}{
		{
			"dataDir doesn't exist",
			func(rootDir string, dataDir string) {},
			func(err error) {
				require.ErrorContains(t, err, "data directory does not exist, cannot continue")
			},
		},
		{
			"dataDir exists and is a file",
			func(rootDir string, dataDir string) {
				require.NoError(t,
					os.WriteFile(
						filepath.Join(rootDir, dataDir),
						[]byte{1, 2, 3},
						0o755,
					),
				)
			},
			func(err error) {
				require.ErrorContains(t, err, "data directory is a file, cannot continue")
			},
		},
		{
			"dataDir contains validator_keys file",
			func(rootDir string, dataDir string) {
				require.NoError(t,
					os.Mkdir(filepath.Join(rootDir, dataDir), 0o755),
				)

				require.NoError(t,
					os.WriteFile(
						filepath.Join(rootDir, dataDir, "validator_keys"),
						[]byte{1, 2, 3},
						0o755,
					),
				)
			},
			func(err error) {
				require.ErrorContains(t, err, "data directory not clean, cannot continue")
			},
		},
		{
			"dataDir contains non-empty validator_keys directory",
			func(rootDir string, dataDir string) {
				require.NoError(t,
					os.MkdirAll(filepath.Join(rootDir, dataDir, "validator_keys"), 0o755),
				)

				require.NoError(t,
					os.WriteFile(
						filepath.Join(rootDir, dataDir, "validator_keys", "keystore-0.json"),
						[]byte{1, 2, 3},
						0o755,
					),
				)
			},
			func(err error) {
				require.ErrorContains(t, err, "data directory not clean, cannot continue")
			},
		},
		{
			"dataDir contains cluster-lock.json file",
			func(rootDir string, dataDir string) {
				require.NoError(t,
					os.Mkdir(filepath.Join(rootDir, dataDir), 0o755),
				)

				require.NoError(t,
					os.WriteFile(
						filepath.Join(rootDir, dataDir, clusterLockFile),
						[]byte{1, 2, 3},
						0o755,
					),
				)
			},
			func(err error) {
				require.ErrorContains(t, err, "data directory not clean, cannot continue")
			},
		},
		{
			"dataDir contains deposit-data-32eth.json file",
			func(rootDir string, dataDir string) {
				require.NoError(t,
					os.Mkdir(filepath.Join(rootDir, dataDir), 0o755),
				)

				require.NoError(t,
					os.WriteFile(
						filepath.Join(rootDir, dataDir, "deposit-data-32eth.json"),
						[]byte{1, 2, 3},
						0o755,
					),
				)
			},
			func(err error) {
				require.ErrorContains(t, err, "data directory not clean, cannot continue")
			},
		},
		{
			"dataDir is clean and does not contains charon-enr-private-key file",
			func(rootDir string, dataDir string) {
				require.NoError(t,
					os.Mkdir(filepath.Join(rootDir, dataDir), 0o755),
				)
			},
			func(err error) {
				require.ErrorContains(t, err, "missing required files, cannot continue")
			},
		},
		{
			"dataDir is clean and contains charon-enr-private-key file",
			func(rootDir string, dataDir string) {
				require.NoError(t,
					os.Mkdir(filepath.Join(rootDir, dataDir), 0o755),
				)

				require.NoError(t,
					os.WriteFile(
						filepath.Join(rootDir, dataDir, "charon-enr-private-key"),
						[]byte{1, 2, 3},
						0o755,
					),
				)
			},
			func(err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			td := t.TempDir()
			tt.prepare(td, "data_dir")

			tt.checkError(checkClearDataDir(t.Context(), filepath.Join(td, "data_dir")))
		})
	}
}

// TestCheckClearDataDirValidatorKeys covers the empty validator_keys directory a container runtime
// leaves behind as a mount point: it is removed only when it is a real, empty directory and the
// rest of the data directory is clean, and is otherwise refused and left untouched.
func TestCheckClearDataDirValidatorKeys(t *testing.T) {
	const (
		removeHint = "remove it manually and retry"
		notClean   = "data directory not clean, cannot continue"
	)

	writeFile := func(t *testing.T, path string) {
		t.Helper()
		require.NoError(t, os.WriteFile(path, []byte{1, 2, 3}, 0o600))
	}

	tests := []struct {
		name string
		// prepare populates dataDir, which already contains charon-enr-private-key.
		prepare func(t *testing.T, dataDir string)
		wantErr string
		// wantKeysDir is whether dataDir/validator_keys still exists afterwards.
		wantKeysDir bool
	}{
		{
			name: "empty directory is removed",
			prepare: func(t *testing.T, dataDir string) {
				t.Helper()
				require.NoError(t, os.Mkdir(filepath.Join(dataDir, "validator_keys"), 0o755))
			},
			wantKeysDir: false,
		},
		{
			name: "empty read-only directory is removed",
			prepare: func(t *testing.T, dataDir string) {
				t.Helper()
				// Removing an entry needs write access to the parent only, like a root owned mount point.
				require.NoError(t, os.Mkdir(filepath.Join(dataDir, "validator_keys"), 0o555))
			},
			wantKeysDir: false,
		},
		{
			name: "hidden file is refused",
			prepare: func(t *testing.T, dataDir string) {
				t.Helper()
				require.NoError(t, os.Mkdir(filepath.Join(dataDir, "validator_keys"), 0o755))
				writeFile(t, filepath.Join(dataDir, "validator_keys", ".hidden"))
			},
			wantErr:     notClean,
			wantKeysDir: true,
		},
		{
			name: "empty subdirectory is refused",
			prepare: func(t *testing.T, dataDir string) {
				t.Helper()
				require.NoError(t, os.MkdirAll(filepath.Join(dataDir, "validator_keys", "sub"), 0o755))
			},
			wantErr:     notClean,
			wantKeysDir: true,
		},
		{
			name: "symlink to an empty directory is refused",
			prepare: func(t *testing.T, dataDir string) {
				t.Helper()

				target := filepath.Join(t.TempDir(), "keys")
				require.NoError(t, os.Mkdir(target, 0o755))
				require.NoError(t, os.Symlink(target, filepath.Join(dataDir, "validator_keys")))
			},
			wantErr:     notClean,
			wantKeysDir: true,
		},
		{
			name: "dangling symlink is refused",
			prepare: func(t *testing.T, dataDir string) {
				t.Helper()
				require.NoError(t, os.Symlink(filepath.Join(t.TempDir(), "missing"), filepath.Join(dataDir, "validator_keys")))
			},
			wantErr:     notClean,
			wantKeysDir: true,
		},
		{
			name: "empty directory is kept when a cluster lock exists",
			prepare: func(t *testing.T, dataDir string) {
				t.Helper()
				require.NoError(t, os.Mkdir(filepath.Join(dataDir, "validator_keys"), 0o755))
				writeFile(t, filepath.Join(dataDir, "cluster-lock.json"))
			},
			wantErr:     notClean,
			wantKeysDir: true,
		},
		{
			name: "empty directory is kept when deposit data exists",
			prepare: func(t *testing.T, dataDir string) {
				t.Helper()
				require.NoError(t, os.Mkdir(filepath.Join(dataDir, "validator_keys"), 0o755))
				writeFile(t, filepath.Join(dataDir, "deposit-data-32eth.json"))
			},
			wantErr:     notClean,
			wantKeysDir: true,
		},
		{
			name: "empty directory is kept when the enr private key is missing",
			prepare: func(t *testing.T, dataDir string) {
				t.Helper()
				require.NoError(t, os.Mkdir(filepath.Join(dataDir, "validator_keys"), 0o755))
				require.NoError(t, os.Remove(filepath.Join(dataDir, "charon-enr-private-key")))
			},
			wantErr:     "missing required files, cannot continue",
			wantKeysDir: true,
		},
		{
			name: "unreadable directory is refused",
			prepare: func(t *testing.T, dataDir string) {
				t.Helper()
				skipIfRoot(t)

				dir := filepath.Join(dataDir, "validator_keys")
				require.NoError(t, os.Mkdir(dir, 0o000))
				t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
			},
			wantErr:     "list directory",
			wantKeysDir: true,
		},
		{
			name: "read-only data directory returns a hint",
			prepare: func(t *testing.T, dataDir string) {
				t.Helper()
				skipIfRoot(t)

				require.NoError(t, os.Mkdir(filepath.Join(dataDir, "validator_keys"), 0o755))
				require.NoError(t, os.Chmod(dataDir, 0o555))
				t.Cleanup(func() { _ = os.Chmod(dataDir, 0o755) })
			},
			wantErr:     removeHint,
			wantKeysDir: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataDir := filepath.Join(t.TempDir(), "data_dir")
			require.NoError(t, os.Mkdir(dataDir, 0o755))
			writeFile(t, filepath.Join(dataDir, "charon-enr-private-key"))

			tt.prepare(t, dataDir)

			var logs bytes.Buffer
			log.InitLogfmtForT(t, zapcore.AddSync(&logs))

			err := checkClearDataDir(t.Context(), dataDir)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				require.NotContains(t, logs.String(), "Removed empty validator_keys directory")
			} else {
				require.NoError(t, err)
				require.Contains(t, logs.String(), "Removed empty validator_keys directory")
			}

			_, statErr := os.Lstat(filepath.Join(dataDir, "validator_keys"))
			if tt.wantKeysDir {
				require.NoError(t, statErr)
			} else {
				require.ErrorIs(t, statErr, fs.ErrNotExist)
			}
		})
	}

	t.Run("dkg can write keys after removal", func(t *testing.T) {
		dataDir := t.TempDir()
		writeFile(t, filepath.Join(dataDir, "charon-enr-private-key"))
		require.NoError(t, os.Mkdir(filepath.Join(dataDir, "validator_keys"), 0o755))

		require.NoError(t, checkClearDataDir(t.Context(), dataDir))
		require.NoError(t, checkWrites(dataDir))
	})
}

// skipIfRoot skips tests relying on permission checks, which root bypasses.
func skipIfRoot(t *testing.T) {
	t.Helper()

	if os.Geteuid() == 0 {
		t.Skip("permission checks don't apply to root")
	}
}
