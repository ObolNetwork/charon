// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package privkeylock

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewInitsAndDelete(t *testing.T) {
	temp := t.TempDir()
	handle, err := New(filepath.Join(temp, "privkeylocktest"), "test")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		require.NoError(t, handle.Run(ctx))
	}()

	cancel()
	time.Sleep(100 * time.Millisecond)

	_, openErr := os.Open(filepath.Join(temp, "privkeylocktest"))
	require.ErrorContains(t, openErr, "no such file or directory")
}

func TestNewTwoInitsAndDelete(t *testing.T) {
	temp := t.TempDir()
	handle, err := New(filepath.Join(temp, "privkeylocktest"), "test")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		require.NoError(t, handle.Run(ctx))
	}()

	defer cancel()

	_, err2 := New(filepath.Join(temp, "privkeylocktest"), "test")
	require.ErrorContains(t, err2, "existing private key lock file found, another charon instance may be running on your machine, if not then you can delete that file")
}

func TestNewAfterGraceWorks(t *testing.T) {
	oldgrace := lockfileGracePeriod()
	defer func() {
		lockfileGracePeriod = func() time.Duration {
			return oldgrace
		}
	}()

	lockfileGracePeriod = func() time.Duration {
		return 500 * time.Millisecond
	}

	temp := t.TempDir()
	handle, err := New(filepath.Join(temp, "privkeylocktest"), "test")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		require.NoError(t, handle.Run(ctx))
	}()

	cancel()
	time.Sleep(500 * time.Millisecond)

	_, err2 := New(filepath.Join(temp, "privkeylocktest"), "test")
	require.NoError(t, err2)
}

func TestNewBeforeGraceDoesntWorks(t *testing.T) {
	temp := t.TempDir()
	handle, err := New(filepath.Join(temp, "privkeylocktest"), "test")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		require.NoError(t, handle.Run(ctx))
	}()

	defer cancel()

	time.Sleep(500 * time.Millisecond)

	_, err2 := New(filepath.Join(temp, "privkeylocktest"), "test")
	require.Error(t, err2)
}
