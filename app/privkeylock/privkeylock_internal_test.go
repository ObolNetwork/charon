// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package privkeylock

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestNewInitsAndDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "privkeylocktest")

	svc, err := New(path, "test")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	var eg errgroup.Group

	eg.Go(func() error {
		return svc.Run(ctx)
	})

	eg.Go(func() error {
		assertFileExists(t, path)
		cancel()

		return nil
	})

	require.NoError(t, eg.Wait())

	_, openErr := os.Open(path)
	require.ErrorIs(t, openErr, os.ErrNotExist)
}

func TestNewTwoInitsAndDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "privkeylocktest")
	ctx, cancel := context.WithCancel(context.Background())

	svc, err := New(path, "test")
	require.NoError(t, err)

	var eg errgroup.Group

	eg.Go(func() error {
		return svc.Run(ctx)
	})

	eg.Go(func() error {
		assertFileExists(t, path)

		_, err := New(path, "test")
		require.ErrorContains(t, err, "existing private key lock file found")

		cancel()

		return nil
	})

	require.NoError(t, eg.Wait())

	_, openErr := os.Open(path)
	require.ErrorIs(t, openErr, os.ErrNotExist)
}

func TestNewAfterGraceWorks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "privkeylocktest")

	err := writeFile(path, "test", time.Now().Add(-time.Hour))
	require.NoError(t, err)

	svc, err := New(path, "test")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.NoError(t, svc.Run(ctx))

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
