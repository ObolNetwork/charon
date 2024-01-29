// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunCreateEnr(t *testing.T) {
	temp := t.TempDir()

	err := runCreateEnrCmd(io.Discard, temp)
	require.NoError(t, err)
}
