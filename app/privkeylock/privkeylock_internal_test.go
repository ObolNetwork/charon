// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package privkeylock

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestService(t *testing.T) {
	tmpDir := t.TempDir()
	privKeyPath := filepath.Join(tmpDir, "privkey")
	lockFilePath := filepath.Join(tmpDir, "cluster-lock.json")
	lockPath := privKeyPath + ".lock"

	// Create test files.
	writeClusterLockFile(t, lockFilePath, "hash123")
	writePrivateKeyFile(t, privKeyPath)

	// Create a stale file that is ignored.
	err := overwritePrivateKeyLockFile(lockPath, "hash123", "test", time.Now().Add(-staleDuration))
	require.NoError(t, err)

	// Create a new service.
	svc, err := New(privKeyPath, lockFilePath, "test")
	require.NoError(t, err)
	// Increase the update period to make the test faster.
	svc.updatePeriod = time.Millisecond

	assertFileExists(t, lockPath)

	// Assert a new service can't be created.
	_, err = New(privKeyPath, lockFilePath, "test")
	require.ErrorContains(t, err, "private key lock file is recently updated")

	// Delete the file so Run will create it again.
	require.NoError(t, os.Remove(lockPath))

	var eg errgroup.Group
	eg.Go(svc.Run) // Run will create the file.

	eg.Go(func() error {
		assertFileExists(t, lockPath)
		svc.Close()

		return nil
	})

	require.NoError(t, eg.Wait())

	// Assert the file is not deleted.
	_, openErr := os.Open(lockPath)
	require.NoError(t, openErr)
}

func TestClusterHashMismatchWithinGracePeriod(t *testing.T) {
	tmpDir := t.TempDir()
	privKeyPath := filepath.Join(tmpDir, "privkey")
	lockFilePath := filepath.Join(tmpDir, "cluster-lock.json")
	lockPath := privKeyPath + ".lock"

	// Create test files.
	writeClusterLockFile(t, lockFilePath, "hash1")
	writePrivateKeyFile(t, privKeyPath)

	// Create a stale but within grace period lock file with hash1.
	err := overwritePrivateKeyLockFile(lockPath, "hash1", "test", time.Now().Add(-staleDuration-time.Second))
	require.NoError(t, err)

	// Update cluster lock file to hash2.
	writeClusterLockFile(t, lockFilePath, "hash2")

	// Try to create service with new hash within grace period - should fail.
	_, err = New(privKeyPath, lockFilePath, "test")
	require.Error(t, err)
	require.ErrorContains(t, err, "different cluster lock hash")
	require.ErrorContains(t, err, "you must wait")
}

func TestClusterHashMismatchAfterGracePeriod(t *testing.T) {
	tmpDir := t.TempDir()
	privKeyPath := filepath.Join(tmpDir, "privkey")
	lockFilePath := filepath.Join(tmpDir, "cluster-lock.json")
	lockPath := privKeyPath + ".lock"

	// Create test files.
	writeClusterLockFile(t, lockFilePath, "hash1")
	writePrivateKeyFile(t, privKeyPath)

	// Create an old lock file with hash1 (beyond grace period).
	err := overwritePrivateKeyLockFile(lockPath, "hash1", "test", time.Now().Add(-gracePeriod-time.Second))
	require.NoError(t, err)

	// Update cluster lock file to hash2.
	writeClusterLockFile(t, lockFilePath, "hash2")

	// Try to create service with new hash after grace period - should succeed.
	_, err = New(privKeyPath, lockFilePath, "test")
	require.NoError(t, err)

	// Verify the new hash is written.
	content, err := os.ReadFile(lockPath)
	require.NoError(t, err)

	var meta metadata

	err = json.Unmarshal(content, &meta)
	require.NoError(t, err)
	require.Equal(t, "hash2", meta.ClusterLockHash)
}

func TestClusterHashMatchWithinGracePeriod(t *testing.T) {
	tmpDir := t.TempDir()
	privKeyPath := filepath.Join(tmpDir, "privkey")
	lockFilePath := filepath.Join(tmpDir, "cluster-lock.json")
	lockPath := privKeyPath + ".lock"

	// Create test files.
	writeClusterLockFile(t, lockFilePath, "hash1")
	writePrivateKeyFile(t, privKeyPath)

	// Create a recent lock file with hash1 (within stale duration).
	err := overwritePrivateKeyLockFile(lockPath, "hash1", "test", time.Now().Add(-time.Second))
	require.NoError(t, err)

	// Try to create service with same hash - should fail due to staleness check.
	_, err = New(privKeyPath, lockFilePath, "test")
	require.Error(t, err)
	require.ErrorContains(t, err, "another charon instance may be running")

	// Now create a stale lock file with same hash (beyond stale duration but within grace period).
	err = overwritePrivateKeyLockFile(lockPath, "hash1", "test", time.Now().Add(-staleDuration-time.Second))
	require.NoError(t, err)

	// Should succeed since hash matches and file is stale.
	_, err = New(privKeyPath, lockFilePath, "test")
	require.NoError(t, err)
}

func TestClusterLockFileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	privKeyPath := filepath.Join(tmpDir, "privkey")
	lockFilePath := filepath.Join(tmpDir, "nonexistent.json")

	// Create test files.
	writePrivateKeyFile(t, privKeyPath)

	// Should succeed when cluster lock file doesn't exist (e.g., during DKG).
	// The cluster lock hash will be empty.
	_, err := New(privKeyPath, lockFilePath, "test")
	require.NoError(t, err)

	// Verify empty cluster hash is written.
	lockPath := privKeyPath + ".lock"
	content, err := os.ReadFile(lockPath)
	require.NoError(t, err)

	var meta metadata

	err = json.Unmarshal(content, &meta)
	require.NoError(t, err)
	require.Empty(t, meta.ClusterLockHash)
}

func assertFileExists(t *testing.T, path string) {
	t.Helper()

	assert.Eventually(t, func() bool {
		_, openErr := os.Open(path)
		return openErr == nil
	}, time.Second, time.Millisecond)
}

// writeClusterLockFile creates a cluster lock file with the given hash.
func writeClusterLockFile(t *testing.T, path, lockHash string) {
	t.Helper()

	content := map[string]any{
		"lock_hash": lockHash,
		"name":      "test-cluster",
	}
	b, err := json.Marshal(content)
	require.NoError(t, err)
	err = os.WriteFile(path, b, 0o644)
	require.NoError(t, err)
}

// writePrivateKeyFile creates a dummy private key file.
func writePrivateKeyFile(t *testing.T, path string) {
	t.Helper()

	err := os.WriteFile(path, []byte("private key content"), 0o644)
	require.NoError(t, err)
}

func TestEmptyHashToHashMigration(t *testing.T) {
	tmpDir := t.TempDir()
	privKeyPath := filepath.Join(tmpDir, "privkey")
	lockFilePath := filepath.Join(tmpDir, "cluster-lock.json")
	lockPath := privKeyPath + ".lock"

	// Create test files.
	writeClusterLockFile(t, lockFilePath, "newhash")
	writePrivateKeyFile(t, privKeyPath)

	// Create a stale lock file with empty cluster hash (migration scenario).
	err := overwritePrivateKeyLockFile(lockPath, "", "test", time.Now().Add(-staleDuration*2))
	require.NoError(t, err)

	// Should succeed - empty hash shouldn't trigger grace period.
	_, err = New(privKeyPath, lockFilePath, "test")
	require.NoError(t, err)

	// Verify the new hash is written.
	content, err := os.ReadFile(lockPath)
	require.NoError(t, err)

	var meta metadata

	err = json.Unmarshal(content, &meta)
	require.NoError(t, err)
	require.Equal(t, "newhash", meta.ClusterLockHash)
}
