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
	ctx, cancel := context.WithCancel(context.Background())

	temp := t.TempDir()
	handle, err := New(filepath.Join(temp, "privkeylocktest"), "test")
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		require.NoError(t, handle.Run(ctx))
		done <- struct{}{}
	}()

	defer func() {
		cancel()
		<-done
	}()

	_, err2 := New(filepath.Join(temp, "privkeylocktest"), "test")
	require.ErrorContains(t, err2, "existing private key lock file found, another charon instance may be running on your machine, if not then you can delete that file")
}

func TestNewAfterGraceWorks(t *testing.T) {
	oldgrace := staleDuration()
	defer func() {
		staleDuration = func() time.Duration {
			return oldgrace
		}

		nowFunc = time.Now
	}()

	staleDuration = func() time.Duration {
		return 500 * time.Millisecond
	}

	nowFunc = func() time.Time {
		return time.Now().Add(-2 * time.Second)
	}

	temp := t.TempDir()
	handle, err := New(filepath.Join(temp, "privkeylocktest"), "test")
	require.NoError(t, err)

	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		require.NoError(t, handle.Run(ctx))
		done <- struct{}{}
	}()

	cancel()

	_, err2 := New(filepath.Join(temp, "privkeylocktest"), "test")
	require.NoError(t, err2)

	<-done
}

func TestNewBeforeGraceDoesntWorks(t *testing.T) {
	defer func() {
		nowFunc = time.Now
	}()

	nowFunc = func() time.Time {
		return time.Now().Add(-2 * time.Second)
	}

	temp := t.TempDir()
	handle, err := New(filepath.Join(temp, "privkeylocktest"), "test")
	require.NoError(t, err)

	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		require.NoError(t, handle.Run(ctx))
		done <- struct{}{}
	}()

	_, err2 := New(filepath.Join(temp, "privkeylocktest"), "test")
	require.Error(t, err2)

	cancel()
	<-done
}
