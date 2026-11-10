// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster/proposerconfig"
)

func TestBuilderConfigHash(t *testing.T) {
	conf := Config{ProposerConfigSeed: proposerconfig.Seed{
		BuilderURLs:                []string{"https://b.example.com", "https://a.example.com"},
		BuilderMinBid:              1,
		BuilderBoostFactor:         100,
		BuilderMaxExecutionPayment: 2,
	}}

	hash := builderConfigHash(conf)
	require.Len(t, hash, 32)

	// The hash is insensitive to builder URL order.
	reordered := conf
	reordered.ProposerConfigSeed.BuilderURLs = []string{"https://a.example.com", "https://b.example.com"}
	require.Equal(t, hash, builderConfigHash(reordered))

	// Each value contributes to the hash.
	for _, mutate := range []func(*Config){
		func(c *Config) { c.ProposerConfigSeed.BuilderURLs = c.ProposerConfigSeed.BuilderURLs[:1] },
		func(c *Config) { c.ProposerConfigSeed.BuilderMinBid++ },
		func(c *Config) { c.ProposerConfigSeed.BuilderBoostFactor++ },
		func(c *Config) { c.ProposerConfigSeed.BuilderMaxExecutionPayment++ },
	} {
		mutated := conf
		mutated.ProposerConfigSeed.BuilderURLs = append([]string(nil), conf.ProposerConfigSeed.BuilderURLs...)
		mutate(&mutated)
		require.NotEqual(t, hash, builderConfigHash(mutated))
	}

	// An unconfigured node still produces a stable non-empty hash.
	require.Len(t, builderConfigHash(Config{}), 32)
}
