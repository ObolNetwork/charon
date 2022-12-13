package main

import (
	"testing"

	"github.com/obolnetwork/charon/testutil"
	"github.com/stretchr/testify/require"
)

func TestEmptyConfig(t *testing.T) {
	var cfg Config
	require.Error(t, initConfig("testdata/none.yaml", &cfg))
}

func TestValidConfig(t *testing.T) {
	var cfg Config
	require.NoError(t, initConfig("testdata/valid.yaml", &cfg))

	testutil.RequireGoldenJSON(t, cfg)
}
