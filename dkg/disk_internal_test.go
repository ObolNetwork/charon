// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
)

func TestLoadDefinition(t *testing.T) {
	tmp := t.TempDir()

	// Valid definition
	lock, _, _ := cluster.NewForT(t, 1, 2, 3, 0)
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
			got, err := loadDefinition(context.Background(), Config{DefFile: tt.defFile, NoVerify: tt.noVerify})
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
				require.ErrorContains(t, err, "data directory doesn't exist, cannot continue")
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
				require.ErrorContains(t, err, "data directory already exists and is a file, cannot continue")
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
			"dataDir contains validator_keys directory",
			func(rootDir string, dataDir string) {
				require.NoError(t,
					os.MkdirAll(filepath.Join(rootDir, dataDir, "validator_keys"), 0o755),
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
						filepath.Join(rootDir, dataDir, "cluster-lock.json"),
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
			"dataDir contains deposit-data.json file",
			func(rootDir string, dataDir string) {
				require.NoError(t,
					os.Mkdir(filepath.Join(rootDir, dataDir), 0o755),
				)

				require.NoError(t,
					os.WriteFile(
						filepath.Join(rootDir, dataDir, "deposit-data.json"),
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

			tt.checkError(checkClearDataDir(filepath.Join(td, "data_dir")))
		})
	}
}
