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

func TestBuilderConfigHash(t *testing.T) {
	conf := Config{
		BuilderURLs:                []string{"https://b.example.com", "https://a.example.com"},
		BuilderMinBid:              1,
		BuilderBoostFactor:         100,
		BuilderMaxExecutionPayment: 2,
	}

	hash := builderConfigHash(conf)
	require.Len(t, hash, 32)

	// The hash is insensitive to builder URL order.
	reordered := conf
	reordered.BuilderURLs = []string{"https://a.example.com", "https://b.example.com"}
	require.Equal(t, hash, builderConfigHash(reordered))

	// Each value contributes to the hash.
	for _, mutate := range []func(*Config){
		func(c *Config) { c.BuilderURLs = c.BuilderURLs[:1] },
		func(c *Config) { c.BuilderMinBid++ },
		func(c *Config) { c.BuilderBoostFactor++ },
		func(c *Config) { c.BuilderMaxExecutionPayment++ },
	} {
		mutated := conf
		mutated.BuilderURLs = append([]string(nil), conf.BuilderURLs...)
		mutate(&mutated)
		require.NotEqual(t, hash, builderConfigHash(mutated))
	}

	// An unconfigured node still produces a stable non-empty hash.
	require.Len(t, builderConfigHash(Config{}), 32)
}
