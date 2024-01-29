// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package privkeylock

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestService(t *testing.T) {
	path := filepath.Join(t.TempDir(), "privkeylocktest")

	// Create a stale file that is ignored.
	err := writeFile(path, "test", time.Now().Add(-staleDuration))
	require.NoError(t, err)

	// Create a new service.
	svc, err := New(path, "test")
	require.NoError(t, err)
	// Increase the update period to make the test faster.
	svc.updatePeriod = time.Millisecond

	assertFileExists(t, path)

	// Assert a new service can't be created.
	_, err = New(path, "test")
	require.ErrorContains(t, err, "existing private key lock file found")

	// Delete the file so Run will create it again.
	require.NoError(t, os.Remove(path))

	var eg errgroup.Group
	eg.Go(svc.Run) // Run will create the file.

	eg.Go(func() error {
		assertFileExists(t, path)
		svc.Close()

		return nil
	})

	require.NoError(t, eg.Wait())

	// Assert the file is deleted.
	_, openErr := os.Open(path)
	require.ErrorIs(t, openErr, os.ErrNotExist)
}

func assertFileExists(t *testing.T, path string) {
	t.Helper()

	assert.Eventually(t, func() bool {
		_, openErr := os.Open(path)
		return openErr == nil
	}, time.Second, time.Millisecond)
}
