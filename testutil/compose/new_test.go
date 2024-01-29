// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package compose_test

import (
	"context"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/compose"
)

//go:generate go test . -update -clean

func TestNewDefaultConfig(t *testing.T) {
	dir := t.TempDir()

	err := compose.New(context.Background(), dir, compose.NewDefaultConfig())
	require.NoError(t, err)

	conf, err := os.ReadFile(path.Join(dir, "config.json"))
	require.NoError(t, err)

	testutil.RequireGoldenBytes(t, conf)
}
