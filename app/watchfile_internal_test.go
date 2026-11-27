// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWatchFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "watched.json")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	changes, err := watchFile(ctx, path)
	require.NoError(t, err)

	// Other files in the directory are ignored.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other.json"), []byte("{}"), 0o644))

	select {
	case <-changes:
		require.Fail(t, "change of another file reported")
	case <-time.After(100 * time.Millisecond):
	}

	// Creating the file and replacing it by rename are reported.
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o644))

	select {
	case _, ok := <-changes:
		require.True(t, ok)
	case <-time.After(5 * time.Second):
		require.Fail(t, "file creation not reported")
	}

	require.NoError(t, os.WriteFile(path+".tmp", []byte("{}"), 0o644))
	require.NoError(t, os.Rename(path+".tmp", path))

	select {
	case _, ok := <-changes:
		require.True(t, ok)
	case <-time.After(5 * time.Second):
		require.Fail(t, "file replacement not reported")
	}

	// Cancelling the context closes the channel, after any notification still pending.
	cancel()

	deadline := time.After(5 * time.Second)

	for closed := false; !closed; {
		select {
		case _, ok := <-changes:
			closed = !ok
		case <-deadline:
			require.Fail(t, "channel not closed")
		}
	}

	// A missing directory fails.
	_, err = watchFile(context.Background(), filepath.Join(dir, "missing", "watched.json"))
	require.ErrorContains(t, err, "watch directory")
}
