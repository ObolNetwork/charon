// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package vcbundle

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListKeystores(t *testing.T) {
	dir := t.TempDir()
	writeTestKeystore(t, dir, 1, "0xBB22")
	writeTestKeystore(t, dir, 0, "aa11")

	got, err := listKeystores(dir)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, "0xaa11", got[0].Pubkey)
	require.Equal(t, filepath.Join(dir, "keystore-0.json"), got[0].KeystorePath)
	require.Equal(t, 0, got[0].Index)
	require.Equal(t, "0xbb22", got[1].Pubkey)
	require.Equal(t, filepath.Join(dir, "keystore-1.txt"), got[1].PasswordPath)
	require.Equal(t, 1, got[1].Index)
}

func TestListKeystoresErrors(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		_, err := listKeystores(t.TempDir())
		require.ErrorContains(t, err, "no keystores found")
	})

	t.Run("missing password", func(t *testing.T) {
		dir := t.TempDir()
		writeTestKeystore(t, dir, 0, "aa11")
		require.NoError(t, os.Remove(filepath.Join(dir, "keystore-0.txt")))

		_, err := listKeystores(dir)
		require.ErrorContains(t, err, "keystore password file not found")
	})

	t.Run("duplicate public key", func(t *testing.T) {
		dir := t.TempDir()
		writeTestKeystore(t, dir, 0, "aa11")
		writeTestKeystore(t, dir, 1, "0xAA11")

		_, err := listKeystores(dir)
		require.ErrorContains(t, err, "duplicate keystore public key")
	})

	t.Run("no public key", func(t *testing.T) {
		dir := t.TempDir()
		writeTestKeystore(t, dir, 0, "")

		_, err := listKeystores(dir)
		require.ErrorContains(t, err, "keystore without public key")
	})
}

// writeTestKeystore writes keystore-<index>.json with the public key and its password file.
func writeTestKeystore(t *testing.T, dir string, index int, pubkey string) {
	t.Helper()

	keystore := fmt.Sprintf(`{"pubkey":%q,"crypto":{},"version":4}`, pubkey)
	require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("keystore-%d.json", index)), []byte(keystore), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("keystore-%d.txt", index)), []byte(fmt.Sprintf("password-%d", index)), 0o600))
}
