// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package featureset_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/featureset"
)

// setup initialises global variable per test.
func setup(t *testing.T) {
	t.Helper()

	err := featureset.Init(context.Background(), featureset.DefaultConfig())
	require.NoError(t, err)
}

func TestConfig(t *testing.T) {
	setup(t)

	err := featureset.Init(context.Background(), featureset.DefaultConfig())
	require.NoError(t, err)

	err = featureset.Init(context.Background(), featureset.Config{
		MinStatus: "alpha",
		Enabled:   []string{"ignored"},
	})
	require.NoError(t, err)

	require.True(t, featureset.Enabled(featureset.MockAlpha))
}

func TestEnableForT(t *testing.T) {
	setup(t)

	testFeature := featureset.Feature("test")
	require.False(t, featureset.Enabled(testFeature))

	featureset.EnableForT(t, testFeature)
	require.True(t, featureset.Enabled(testFeature))

	featureset.DisableForT(t, testFeature)
	require.False(t, featureset.Enabled(testFeature))
}

func TestEnableGnosisBlockHotfixIfNotDisabled(t *testing.T) {
	ctx := context.Background()
	config := featureset.DefaultConfig()

	t.Run("not disabled explicitly", func(t *testing.T) {
		err := featureset.Init(ctx, config)
		require.NoError(t, err)

		featureset.EnableGnosisBlockHotfixIfNotDisabled(ctx, config)
		require.True(t, featureset.Enabled(featureset.GnosisBlockHotfix))
	})

	t.Run("disabled explicitly", func(t *testing.T) {
		config.Disabled = append(config.Disabled, string(featureset.GnosisBlockHotfix))

		err := featureset.Init(ctx, config)
		require.NoError(t, err)

		featureset.EnableGnosisBlockHotfixIfNotDisabled(ctx, config)
		require.False(t, featureset.Enabled(featureset.GnosisBlockHotfix))
	})
}
