// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package vcbundle

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListKeystores(t *testing.T) {
	dir := t.TempDir()
	writeTestKeystore(t, dir, 1, "0x"+strings.ToUpper(testPubkeyB[2:]))
	writeTestKeystore(t, dir, 0, testPubkeyA[2:])

	got, err := listKeystores(dir)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, testPubkeyA, got[0].Pubkey)
	require.Equal(t, filepath.Join(dir, "keystore-0.json"), got[0].KeystorePath)
	require.Equal(t, 0, got[0].Index)
	require.Equal(t, testPubkeyB, got[1].Pubkey)
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
		writeTestKeystore(t, dir, 0, testPubkeyA[2:])
		require.NoError(t, os.Remove(filepath.Join(dir, "keystore-0.txt")))

		_, err := listKeystores(dir)
		require.ErrorContains(t, err, "keystore password file not found")
	})

	t.Run("duplicate public key", func(t *testing.T) {
		dir := t.TempDir()
		writeTestKeystore(t, dir, 0, testPubkeyA[2:])
		writeTestKeystore(t, dir, 1, upperPubkeyA)

		_, err := listKeystores(dir)
		require.ErrorContains(t, err, "duplicate keystore public key")
	})

	t.Run("no public key", func(t *testing.T) {
		dir := t.TempDir()
		writeTestKeystore(t, dir, 0, "")

		_, err := listKeystores(dir)
		require.ErrorContains(t, err, "keystore without public key")
	})

	// The public key names directories of the output.
	for name, pubkey := range map[string]string{
		"path public key":  "../../escape",
		"short public key": "0xaa11",
		"long public key":  testPubkeyA + "00",
		"not hex":          "0xzz11" + testPubkeyA[6:],
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestKeystore(t, dir, 0, pubkey)

			_, err := listKeystores(dir)
			require.ErrorContains(t, err, "keystore public key is not 48 bytes of hex")
		})
	}
}

// writeTestKeystore writes keystore-<index>.json with the public key and its password file.
func writeTestKeystore(t *testing.T, dir string, index int, pubkey string) {
	t.Helper()

	keystore := fmt.Sprintf(`{"pubkey":%q,"crypto":{},"version":4}`, pubkey)
	require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("keystore-%d.json", index)), []byte(keystore), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("keystore-%d.txt", index)), []byte(fmt.Sprintf("password-%d", index)), 0o600))
}
