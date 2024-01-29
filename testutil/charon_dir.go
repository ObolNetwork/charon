// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package testutil

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

func CreateTempCharonDir(t *testing.T) string {
	t.Helper()

	tmp := t.TempDir()
	dir := path.Join(tmp, ".charon")
	require.NoError(t, os.Mkdir(dir, 0o755))

	t.Cleanup(func() {
		require.NoError(t, os.RemoveAll(dir))
	})

	return dir
}
