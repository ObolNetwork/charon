// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

//nolint:testpackage // needs to overwrite grace period function without exposing it
package privkeylock

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewInitsAndDelete(t *testing.T) {
	temp := t.TempDir()
	cleanFunc, err := New(filepath.Join(temp, "privkeylocktest"), "test")
	require.NoError(t, err)
	require.NotNil(t, cleanFunc)
	require.NoError(t, cleanFunc())
	_, openErr := os.Open(filepath.Join(temp, "privkeylocktest"))
	require.ErrorContains(t, openErr, "no such file or directory")
}

func TestNewTwoInitsAndDelete(t *testing.T) {
	temp := t.TempDir()
	cleanFunc, err := New(filepath.Join(temp, "privkeylocktest"), "test")
	require.NoError(t, err)
	require.NotNil(t, cleanFunc)

	cleanFunc2, err2 := New(filepath.Join(temp, "privkeylocktest"), "test")
	require.ErrorContains(t, err2, "existing private key lock file found, another charon instance may be running on your machine, if not then you can delete that file")
	require.Nil(t, cleanFunc2)

	require.NoError(t, cleanFunc())
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
	cleanFunc, err := New(filepath.Join(temp, "privkeylocktest"), "test")
	require.NoError(t, err)
	require.NotNil(t, cleanFunc)

	time.Sleep(500 * time.Millisecond)

	cleanFunc2, err2 := New(filepath.Join(temp, "privkeylocktest"), "test")
	require.NoError(t, err2)
	require.NoError(t, cleanFunc2())
}

func TestNewBeforeGraceDoesntWorks(t *testing.T) {
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
	cleanFunc, err := New(filepath.Join(temp, "privkeylocktest"), "test")
	require.NoError(t, err)
	require.NotNil(t, cleanFunc)

	time.Sleep(100 * time.Millisecond)

	cleanFunc2, err2 := New(filepath.Join(temp, "privkeylocktest"), "test")
	require.ErrorContains(t, err2, "existing private key lock file found, another charon instance may be running on your machine, if not then you can delete that file")
	require.Nil(t, cleanFunc2)
}
