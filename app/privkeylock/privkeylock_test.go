// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package privkeylock_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/privkeylock"
)

func TestNewInitsAndDelete(t *testing.T) {
	temp := t.TempDir()
	cleanFunc, err := privkeylock.New(filepath.Join(temp, "privkeylocktest"), "test")
	require.NoError(t, err)
	require.NotNil(t, cleanFunc)
	require.NoError(t, cleanFunc())
	_, openErr := os.Open(filepath.Join(temp, "privkeylocktest"))
	require.ErrorContains(t, openErr, "no such file or directory")
}

func TestNewTwoInitsAndDelete(t *testing.T) {
	temp := t.TempDir()
	cleanFunc, err := privkeylock.New(filepath.Join(temp, "privkeylocktest"), "test")
	require.NoError(t, err)
	require.NotNil(t, cleanFunc)

	cleanFunc2, err2 := privkeylock.New(filepath.Join(temp, "privkeylocktest"), "test")
	require.ErrorContains(t, err2, "existing private key lock file found, another charon instance may be running on your machine, if not then you can delete that file")
	require.Nil(t, cleanFunc2)

	require.NoError(t, cleanFunc())
}
