// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster/proposerconfig"
)

func TestBuilderConfig(t *testing.T) {
	// Each configured builder is an entry without its auth: the fetcher adds the aggregated
	// builder request auth per proposal. MinBid and BuilderBoostFactor also gate P2P bids.
	conf := Config{ProposerConfigSeed: proposerconfig.Seed{
		BuilderURLs:                []string{"https://a.example.com", "https://b.example.com"},
		BuilderMinBid:              7,
		BuilderBoostFactor:         120,
		BuilderMaxExecutionPayment: 3,
	}}

	cfg := builderConfig(conf)
	require.EqualValues(t, 7, cfg.MinBid)
	require.EqualValues(t, 120, cfg.BuilderBoostFactor)
	require.Len(t, cfg.Builders, 2)

	for i, entry := range cfg.Builders {
		require.Equal(t, []byte(conf.ProposerConfigSeed.BuilderURLs[i]), entry.URL)
		require.Nil(t, entry.Auth)
		require.Empty(t, entry.BuilderPubkeys)
		require.EqualValues(t, 3, entry.MaxExecutionPayment)
		require.EqualValues(t, 7, entry.MinBid)
		require.EqualValues(t, 120, entry.BuilderBoostFactor)
	}

	require.Empty(t, builderConfig(Config{ProposerConfigSeed: proposerconfig.Seed{BuilderMinBid: 7}}).Builders)
}

func TestBuilderConfigured(t *testing.T) {
	require.False(t, builderConfigured(Config{}))
	// The other builder values only apply alongside builder URLs, the flags reject them without.
	require.False(t, builderConfigured(Config{ProposerConfigSeed: proposerconfig.Seed{BuilderMinBid: 1, BuilderBoostFactor: 99, BuilderMaxExecutionPayment: 1}}))

	require.True(t, builderConfigured(Config{ProposerConfigSeed: proposerconfig.Seed{BuilderURLs: []string{"https://builder.example.com"}}}))
}

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

func TestBuilderHosts(t *testing.T) {
	hosts, err := builderHosts(Config{ProposerConfigSeed: proposerconfig.Seed{BuilderURLs: []string{"https://Relay-A.example.com:443/path", "http://relay-b.example.com"}}})
	require.NoError(t, err)
	require.Equal(t, []string{"relay-a.example.com", "relay-b.example.com"}, hosts)

	hosts, err = builderHosts(Config{})
	require.NoError(t, err)
	require.Empty(t, hosts)
}

func TestWithoutUserInfo(t *testing.T) {
	require.Equal(t, "https://relay.example.com", withoutUserInfo("https://0xabc@relay.example.com"))
	require.Equal(t, "https://builder.example.com/path", withoutUserInfo("https://user:secret@builder.example.com/path"))
	require.Equal(t, "http://mev-boost:18550", withoutUserInfo("http://mev-boost:18550"))
}
