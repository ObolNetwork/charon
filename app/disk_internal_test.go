// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"os"
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

func TestCopyFile(t *testing.T) {
	tempDir := t.TempDir()
	srcFile := tempDir + "/src.txt"
	destFile := tempDir + "/dest.txt"

	// Create a source file with some content
	err := os.WriteFile(srcFile, []byte("Hello, World!"), 0o644)
	require.NoError(t, err)

	err = CopyFile(srcFile, destFile)
	require.NoError(t, err)

	// Verify the destination file has the same content
	destContent, err := os.ReadFile(destFile)
	require.NoError(t, err)
	require.Equal(t, "Hello, World!", string(destContent))
}
