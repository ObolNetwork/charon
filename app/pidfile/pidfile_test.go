// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pidfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/pidfile"
)

func TestNewInitsAndDelete(t *testing.T) {
	temp := t.TempDir()
	cleanFunc, err := pidfile.New(temp, "test")
	require.NoError(t, err)
	require.NotNil(t, cleanFunc)
	require.NoError(t, cleanFunc())
	_, openErr := os.Open(filepath.Join(temp, "charon-pidfile"))
	require.ErrorContains(t, openErr, "no such file or directory")
}

func TestNewTwoInitsAndDelete(t *testing.T) {
	temp := t.TempDir()
	cleanFunc, err := pidfile.New(temp, "test")
	require.NoError(t, err)
	require.NotNil(t, cleanFunc)

	cleanFunc2, err2 := pidfile.New(temp, "test")
	require.ErrorContains(t, err2, "another instance of charon is running on the selected data directory")
	require.Nil(t, cleanFunc2)

	require.NoError(t, cleanFunc())
}
