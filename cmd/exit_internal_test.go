// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
)

func TestLoadExitLockNoVerify(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 1, 3, 4, 0, rand.New(rand.NewSource(0)))
	lock.SignatureAggregate = bytes.Repeat([]byte{0x01}, 96) // Right length, invalid signature.

	b, err := json.Marshal(lock)
	require.NoError(t, err)

	lockPath := filepath.Join(t.TempDir(), "cluster-lock.json")
	require.NoError(t, os.WriteFile(lockPath, b, 0o600))

	_, err = loadExitLock(t.Context(), exitConfig{LockFilePath: lockPath})
	require.ErrorContains(t, err, "verify lock signature aggregate")

	got, err := loadExitLock(t.Context(), exitConfig{LockFilePath: lockPath, NoVerify: true})
	require.NoError(t, err)
	require.Equal(t, lock.LockHash, got.LockHash)
}
