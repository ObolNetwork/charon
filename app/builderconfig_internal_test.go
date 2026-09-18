// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuilderConfigured(t *testing.T) {
	require.False(t, builderConfigured(Config{}))
	// The other builder values only apply alongside builder URLs, the flags reject them without.
	require.False(t, builderConfigured(Config{BuilderMinBid: 1, BuilderBoostFactor: 99, BuilderMaxExecutionPayment: 1}))

	require.True(t, builderConfigured(Config{BuilderURLs: []string{"https://builder.example.com"}}))
}
