// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package testutil_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
)

func TestCompareDirectories(t *testing.T) {
	tests := []struct {
		name        string
		setupDirs   func(t *testing.T) (dir1, dir2 string)
		expectError bool
		errorMsg    string
	}{
		{
			name: "identical_directories",
			setupDirs: func(t *testing.T) (string, string) {
				t.Helper()
				dir1 := t.TempDir()
				testFiles := map[string]string{
					"file1.txt":             "content1",
					"nested/file2.json":     `{"key": "value"}`,
					"nested/deep/file3.md":  "# Header\nContent",
					"binary.bin":            "\x00\x01\x02\x03",
					"special_chars_äöü.txt": "Special characters: äöüß",
				}

				for relPath, content := range testFiles {
					fullPath := filepath.Join(dir1, relPath)
					require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0o755))
					require.NoError(t, os.WriteFile(fullPath, []byte(content), 0o644))
				}

				dir2 := t.TempDir()
				require.NoError(t, os.CopyFS(dir2, os.DirFS(dir1)))

				return dir1, dir2
			},
			expectError: false,
		},
		{
			name: "missing_file",
			setupDirs: func(t *testing.T) (string, string) {
				t.Helper()
				dir1 := t.TempDir()
				dir2 := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir1, "file.txt"), []byte("content"), 0o644))

				return dir1, dir2
			},
			expectError: true,
			errorMsg:    "file should exist in extracted content",
		},
		{
			name: "extra_file",
			setupDirs: func(t *testing.T) (string, string) {
				t.Helper()
				dir1 := t.TempDir()
				dir2 := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir2, "file.txt"), []byte("content"), 0o644))

				return dir1, dir2
			},
			expectError: true,
			errorMsg:    "path should not exist in extracted content",
		},
		{
			name: "extra_directory",
			setupDirs: func(t *testing.T) (string, string) {
				t.Helper()
				dir1 := t.TempDir()
				dir2 := t.TempDir()
				require.NoError(t, os.Mkdir(filepath.Join(dir2, "sub"), 0o755))

				return dir1, dir2
			},
			expectError: true,
			errorMsg:    "path should not exist in extracted content",
		},
		{
			name: "different_content",
			setupDirs: func(t *testing.T) (string, string) {
				t.Helper()
				dir1 := t.TempDir()
				dir2 := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir1, "file.txt"), []byte("content1"), 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dir2, "file.txt"), []byte("content2"), 0o644))

				return dir1, dir2
			},
			expectError: true,
			errorMsg:    "file content mismatch",
		},
		{
			name: "different_sizes",
			setupDirs: func(t *testing.T) (string, string) {
				t.Helper()
				dir1 := t.TempDir()
				dir2 := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir1, "file.txt"), []byte("short"), 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dir2, "file.txt"), []byte("much longer content"), 0o644))

				return dir1, dir2
			},
			expectError: true,
			errorMsg:    "file size mismatch",
		},
		{
			name: "missing_directory",
			setupDirs: func(t *testing.T) (string, string) {
				t.Helper()
				dir1 := t.TempDir()
				dir2 := t.TempDir()
				nestedDir := filepath.Join(dir1, "nested", "deep")
				require.NoError(t, os.MkdirAll(nestedDir, 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(nestedDir, "file.txt"), []byte("content"), 0o644))

				return dir1, dir2
			},
			expectError: true,
			errorMsg:    "directory should exist in extracted content",
		},
		{
			name: "file_vs_directory",
			setupDirs: func(t *testing.T) (string, string) {
				t.Helper()
				dir1 := t.TempDir()
				dir2 := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir1, "item"), []byte("content"), 0o644))
				require.NoError(t, os.MkdirAll(filepath.Join(dir2, "item"), 0o755))

				return dir1, dir2
			},
			expectError: true,
			errorMsg:    "file size mismatch",
		},
		{
			name: "directory_vs_file",
			setupDirs: func(t *testing.T) (string, string) {
				t.Helper()
				dir1 := t.TempDir()
				dir2 := t.TempDir()
				require.NoError(t, os.MkdirAll(filepath.Join(dir1, "item"), 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(dir2, "item"), []byte("content"), 0o644))

				return dir1, dir2
			},
			expectError: true,
			errorMsg:    "path is not a directory",
		},
		{
			name: "complex_structure",
			setupDirs: func(t *testing.T) (string, string) {
				t.Helper()
				dir1 := t.TempDir()
				dir2 := t.TempDir()
				files := map[string]string{
					"root.txt":                       "root content",
					"validator_keys/keystore-1.json": `{"crypto": {"cipher": "test"}}`,
					"validator_keys/keystore-2.json": `{"crypto": {"cipher": "test"}}`,
					"nested/level1/level2/deep.yaml": "key: value\narray:\n  - item1\n  - item2",
					"cluster-lock.json":              `{"lock_hash": "0xabc"}`,
					"deposit_data.json":              `[{"pubkey": "0x123"}]`,
					"empty_dir/placeholder.txt":      "",
					"binary_data.bin":                "\x00\x01\x02\x03\xFF\xFE\xFD",
				}

				for relPath, content := range files {
					for _, dir := range []string{dir1, dir2} {
						fullPath := filepath.Join(dir, relPath)
						require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0o755))
						require.NoError(t, os.WriteFile(fullPath, []byte(content), 0o644))
					}
				}

				return dir1, dir2
			},
			expectError: false,
		},
		{
			name: "empty_directories",
			setupDirs: func(t *testing.T) (string, string) {
				t.Helper()
				return t.TempDir(), t.TempDir()
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir1, dir2 := tt.setupDirs(t)
			err := testutil.CompareDirectories(dir1, dir2)

			if tt.expectError {
				require.Error(t, err, "Expected error for test case: %s", tt.name)

				if tt.errorMsg != "" {
					require.Contains(t, err.Error(), tt.errorMsg, "Error message should contain expected text")
				}
			} else {
				require.NoError(t, err, "Expected no error for test case: %s", tt.name)
			}
		})
	}
}
