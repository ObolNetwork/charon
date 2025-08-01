// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth1wrap"
)

func TestLoadClusterManifest(t *testing.T) {
	conf := Config{
		LockFile: "testdata/test-cluster-lock.json",
		NoVerify: true,
	}

	eth1Cl := eth1wrap.NewDefaultEthClientRunner("")
	go eth1Cl.Run(t.Context())

	cluster, err := loadClusterManifest(t.Context(), conf, eth1Cl)
	require.NoError(t, err)
	require.NotNil(t, cluster)
	require.Len(t, cluster.GetValidators(), 2)
}

func TestFileExists(t *testing.T) {
	tempDir := t.TempDir()

	tmpFile, err := os.CreateTemp(tempDir, "testfile")
	require.NoError(t, err)

	require.NoError(t, os.Remove(tmpFile.Name()))

	exists := FileExists(tmpFile.Name())
	require.False(t, exists)
}

func TestCreateNewEmptyDir(t *testing.T) {
	tempDir := t.TempDir()
	newDir := filepath.Join(tempDir, "new-cluster")

	// Positive case: create new empty dir
	err := CreateNewEmptyDir(newDir)
	require.NoError(t, err)

	_, err = os.Stat(newDir)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(newDir, "testfile.txt"), []byte("test"), 0o644)
	require.NoError(t, err)

	// Negative case: directory not empty
	err = CreateNewEmptyDir(newDir)
	require.ErrorContains(t, err, "directory not empty")

	// Negative case: path exists as a file
	filePath := filepath.Join(tempDir, "somefile")
	err = os.WriteFile(filePath, []byte("data"), 0o644)
	require.NoError(t, err)

	err = CreateNewEmptyDir(filePath)
	require.ErrorContains(t, err, "not a directory")

	// Negative case: parent directory does not exist
	nonExistentParent := filepath.Join(tempDir, "doesnotexist", "child")
	err = CreateNewEmptyDir(nonExistentParent)
	require.Error(t, err)
}

func TestCopyFile(t *testing.T) {
	tempDir := t.TempDir()
	srcFile := filepath.Join(tempDir, "src.txt")
	destFile := filepath.Join(tempDir, "dest.txt")

	// Create a source file with some content
	err := os.WriteFile(srcFile, []byte("Hello, World!"), 0o644)
	require.NoError(t, err)

	err = CopyFile(srcFile, destFile)
	require.NoError(t, err)

	// Verify the destination file has the same content
	destContent, err := os.ReadFile(destFile)
	require.NoError(t, err)
	require.Equal(t, "Hello, World!", string(destContent))

	// Negative case: source file does not exist
	nonExistentSrc := filepath.Join(tempDir, "doesnotexist.txt")
	err = CopyFile(nonExistentSrc, filepath.Join(tempDir, "shouldnotexist.txt"))
	require.Error(t, err)

	// Negative case: destination path is a directory
	destDir := filepath.Join(tempDir, "destdir")
	err = os.Mkdir(destDir, 0o755)
	require.NoError(t, err)
	err = CopyFile(srcFile, destDir)
	require.Error(t, err)

	// Negative case: source path is a directory
	srcDir := filepath.Join(tempDir, "srcdir")
	err = os.Mkdir(srcDir, 0o755)
	require.NoError(t, err)
	err = CopyFile(srcDir, filepath.Join(tempDir, "dest2.txt"))
	require.Error(t, err)
}
