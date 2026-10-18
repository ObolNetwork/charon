// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuilderConfig(t *testing.T) {
	// Each configured builder is an entry without its auth: the fetcher adds the aggregated
	// builder request auth per proposal. MinBid and BuilderBoostFactor also gate P2P bids.
	conf := Config{
		BuilderURLs:                []string{"https://a.example.com", "https://b.example.com"},
		BuilderMinBid:              7,
		BuilderBoostFactor:         120,
		BuilderMaxExecutionPayment: 3,
	}

	cfg := builderConfig(conf)
	require.EqualValues(t, 7, cfg.MinBid)
	require.EqualValues(t, 120, cfg.BuilderBoostFactor)
	require.Len(t, cfg.Builders, 2)

	for i, entry := range cfg.Builders {
		require.Equal(t, []byte(conf.BuilderURLs[i]), entry.URL)
		require.Nil(t, entry.Auth)
		require.Empty(t, entry.BuilderPubkeys)
		require.EqualValues(t, 3, entry.MaxExecutionPayment)
		require.EqualValues(t, 7, entry.MinBid)
		require.EqualValues(t, 120, entry.BuilderBoostFactor)
	}

	require.Empty(t, builderConfig(Config{BuilderMinBid: 7}).Builders)
}

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

func TestBuilderHosts(t *testing.T) {
	hosts, err := builderHosts(Config{BuilderURLs: []string{"https://Relay-A.example.com:443/path", "http://relay-b.example.com"}})
	require.NoError(t, err)
	require.Equal(t, []string{"relay-a.example.com", "relay-b.example.com"}, hosts)

	hosts, err = builderHosts(Config{})
	require.NoError(t, err)
	require.Empty(t, hosts)
}
