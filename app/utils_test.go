// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/testutil"
)

func TestHex7(t *testing.T) {
	someHash, err := hex.DecodeString("433287d255abf237992d2279af5b1a1bb2c3d7124c97906edd848ebbb541a1c7")
	require.NoError(t, err)

	tests := []struct {
		input    []byte
		expected string
	}{
		{someHash, "433287d"},
		{[]byte("aaa"), "616161"},
		{[]byte(""), ""},
	}

	for _, test := range tests {
		result := app.Hex7(test.input)
		require.Equal(t, test.expected, result, "Hex7 should return the first 7 hex characters of the input")
	}
}

func TestBundleOutput(t *testing.T) {
	// Create a temporary directory for testing
	testDir := t.TempDir()

	// Create a complex file tree structure
	testFiles := map[string]string{
		"root_file.txt":                  "This is a root file content",
		"nested/level1.json":             `{"key": "value", "number": 42}`,
		"nested/deep/level2.md":          "# Deep Nested File\n\nThis is markdown content.",
		"nested/deep/deeper/level3.yaml": "key: value\nlist:\n  - item1\n  - item2",
		"validator_keys/keystore-1.json": `{"crypto": {"cipher": "test"}, "pubkey": "0x123"}`,
		"validator_keys/keystore-2.json": `{"crypto": {"cipher": "test"}, "pubkey": "0x456"}`,
		"cluster-lock.json":              `{"lock_hash": "0xabc", "definition": {}}`,
		"deposit_data.json":              `[{"pubkey": "0x123", "amount": 32000000000}]`,
		"empty_dir/placeholder.txt":      "",
		"binary_file.bin":                "\x00\x01\x02\x03\xFF\xFE\xFD",
		"special_chars_äöü.txt":          "File with special characters: äöüß",
	}

	// Create all test files and directories
	for relPath, content := range testFiles {
		fullPath := filepath.Join(testDir, relPath)
		require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0o755))
		require.NoError(t, os.WriteFile(fullPath, []byte(content), 0o644))
	}

	// Create a backup of the original structure for comparison
	backupDir := t.TempDir()
	require.NoError(t, os.CopyFS(backupDir, os.DirFS(testDir)))

	// Call BundleOutput to create the tar.gz archive
	archiveName := "test_bundle.tar.gz"
	err := app.BundleOutput(testDir, archiveName)
	require.NoError(t, err, "BundleOutput should succeed")

	// Verify that the archive file exists and is only accessible by its owner
	archivePath := filepath.Join(testDir, archiveName)
	info, err := os.Stat(archivePath)
	require.NoError(t, err, "Archive file should exist")
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "Archive should be owner read/write only")

	// Verify that original files are deleted (except the archive)
	entries, err := os.ReadDir(testDir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "Only the archive file should remain")
	require.Equal(t, archiveName, entries[0].Name(), "Only the archive should remain")

	// Extract the archive to a new directory
	extractDir := t.TempDir()
	err = testutil.ExtractArchive(archivePath, extractDir)
	require.NoError(t, err, "Archive extraction should succeed")

	// Compare the extracted content with the original backup
	err = testutil.CompareDirectories(backupDir, extractDir)
	require.NoError(t, err, "Extracted content should match original")
}

func TestBundleOutputExistingArchive(t *testing.T) {
	testDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(testDir, "charon-enr-private-key"), []byte("secret"), 0o600))

	// A world-readable archive left over from a previous run must be restricted too.
	archivePath := filepath.Join(testDir, "test_bundle.tar.gz")
	require.NoError(t, os.WriteFile(archivePath, []byte("stale"), 0o644))

	require.NoError(t, app.BundleOutput(testDir, "test_bundle.tar.gz"))

	info, err := os.Stat(archivePath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "Archive should be owner read/write only")

	// Only the archive is left: no temporary file, no original.
	entries, err := os.ReadDir(testDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	// The stale archive is replaced, not archived.
	extractDir := t.TempDir()
	require.NoError(t, testutil.ExtractArchive(archivePath, extractDir))
	entries, err = os.ReadDir(extractDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	b, err := os.ReadFile(filepath.Join(extractDir, "charon-enr-private-key"))
	require.NoError(t, err)
	require.Equal(t, "secret", string(b))
}

func TestBundleOutputRelativeDir(t *testing.T) {
	// The CLI defaults are relative: "./" for create cluster and ".charon" for dkg.
	for _, dir := range []string{"./", ".", "sub", "sub/"} {
		t.Run(dir, func(t *testing.T) {
			t.Chdir(t.TempDir())
			require.NoError(t, os.MkdirAll(dir, 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "charon-enr-private-key"), []byte("secret"), 0o600))

			// A temporary file left by an interrupted run is neither archived nor kept.
			stale := filepath.Join(dir, "test_bundle.tar.gz.tmp-123")
			require.NoError(t, os.WriteFile(stale, []byte("partial"), 0o600))

			require.NoError(t, app.BundleOutput(dir, "test_bundle.tar.gz"))

			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			require.Len(t, entries, 1)
			require.Equal(t, "test_bundle.tar.gz", entries[0].Name())

			extractDir := t.TempDir()
			require.NoError(t, testutil.ExtractArchive(filepath.Join(dir, "test_bundle.tar.gz"), extractDir))
			entries, err = os.ReadDir(extractDir)
			require.NoError(t, err)
			require.Len(t, entries, 1)

			b, err := os.ReadFile(filepath.Join(extractDir, "charon-enr-private-key"))
			require.NoError(t, err)
			require.Equal(t, "secret", string(b))
		})
	}
}

func TestBundleOutputFailureKeepsOriginals(t *testing.T) {
	testDir := t.TempDir()
	keyPath := filepath.Join(testDir, "charon-enr-private-key")
	require.NoError(t, os.WriteFile(keyPath, []byte("secret"), 0o600))

	// An unreadable file makes archiving fail part way through.
	unreadable := filepath.Join(testDir, "unreadable")
	require.NoError(t, os.WriteFile(unreadable, []byte("x"), 0o000))

	if _, err := os.ReadFile(unreadable); err == nil {
		t.Skip("running as a user that ignores file permissions")
	}

	require.Error(t, app.BundleOutput(testDir, "test_bundle.tar.gz"))

	// The originals are kept and no partial or temporary archive is left behind.
	b, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	require.Equal(t, "secret", string(b))

	entries, err := os.ReadDir(testDir)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	// Once the cause is fixed, a rerun succeeds and bundles exactly the originals.
	require.NoError(t, os.Chmod(unreadable, 0o600))
	require.NoError(t, app.BundleOutput(testDir, "test_bundle.tar.gz"))

	entries, err = os.ReadDir(testDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "test_bundle.tar.gz", entries[0].Name())

	extractDir := t.TempDir()
	require.NoError(t, testutil.ExtractArchive(filepath.Join(testDir, "test_bundle.tar.gz"), extractDir))
	entries, err = os.ReadDir(extractDir)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	b, err = os.ReadFile(filepath.Join(extractDir, "charon-enr-private-key"))
	require.NoError(t, err)
	require.Equal(t, "secret", string(b))
	b, err = os.ReadFile(filepath.Join(extractDir, "unreadable"))
	require.NoError(t, err)
	require.Equal(t, "x", string(b))
}
