// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
)

func TestWriteProposerConfigFile(t *testing.T) {
	const (
		dv      = 4
		nodes   = 4
		peerIdx = 2
	)

	lock, _, _ := cluster.NewForT(t, dv, nodes, nodes, 0, rand.New(rand.NewSource(0)))

	dir := t.TempDir()
	conf := Config{
		LockFile:         filepath.Join(dir, "cluster-lock.json"),
		BuilderAPI:       true,
		ProposerGasLimit: 200_000_000,
	}
	nodeIdx := cluster.NodeIdx{PeerIdx: peerIdx, ShareIdx: peerIdx + 1}

	path := filepath.Join(dir, proposerConfigDir, proposerConfigFilename)

	// Override the first validator's fee recipient (mimicking builder registration
	// overrides), let the second fall back to its lock address, and give the
	// remaining two identical fee recipients so they form the majority.
	overridePubkey, err := core.PubKeyFromBytes(lock.Validators[0].PubKey)
	require.NoError(t, err)

	lockFallbackPubkey, err := core.PubKeyFromBytes(lock.Validators[1].PubKey)
	require.NoError(t, err)

	const (
		overrideAddr = "0xcccccccccccccccccccccccccccccccccccccccc"
		majorityAddr = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)

	feeRecipientFunc := func(pubkey core.PubKey) string {
		switch pubkey {
		case overridePubkey:
			return overrideAddr
		case lockFallbackPubkey:
			return "" // Exercise the lock fallback.
		default:
			return majorityAddr
		}
	}

	created, err := writeProposerConfigFile(conf, &lock, nodeIdx, feeRecipientFunc)
	require.NoError(t, err)
	require.True(t, created)

	b, err := os.ReadFile(path)
	require.NoError(t, err)

	var config proposerConfigJSON

	require.NoError(t, json.Unmarshal(b, &config))
	require.EqualValues(t, 1, config.Version)

	feeRecipients := lock.FeeRecipientAddresses()

	pubshare := func(vi int) string {
		share, err := lock.Validators[vi].PublicShare(peerIdx)
		require.NoError(t, err)

		return fmt.Sprintf("%#x", share)
	}

	// The default config holds the majority fee recipient (validators 2 and 3) and the
	// configured proposer gas limit.
	require.Equal(t, majorityAddr, config.DefaultConfig.FeeRecipient)
	require.Equal(t, "200000000", config.DefaultConfig.GasLimit)
	require.Nil(t, config.DefaultConfig.Builder) // No builder URLs configured.

	// The two diverging validators get entries carrying only their fee recipient.
	require.Len(t, config.ProposerConfig, 2)
	require.Equal(t, proposerSettingsJSON{FeeRecipient: overrideAddr}, config.ProposerConfig[pubshare(0)])
	require.Equal(t, proposerSettingsJSON{FeeRecipient: feeRecipients[1]}, config.ProposerConfig[pubshare(1)])

	// No pre-gloas legacy fields in the charon schema.
	require.NotContains(t, string(b), "enabled")
	require.NotContains(t, string(b), "min_bid")

	// An existing file is never modified.
	require.NoError(t, os.WriteFile(path, []byte("operator managed"), 0o644))

	created, err = writeProposerConfigFile(conf, &lock, nodeIdx, feeRecipientFunc)
	require.NoError(t, err)
	require.False(t, created)

	b, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "operator managed", string(b))

	// A directory occupying the file path is an error.
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.Mkdir(path, 0o755))

	_, err = writeProposerConfigFile(conf, &lock, nodeIdx, feeRecipientFunc)
	require.ErrorContains(t, err, "is a directory")
}

func TestWriteProposerConfigFileBuilder(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 1, 4, 4, 0, rand.New(rand.NewSource(0)))

	nodeIdx := cluster.NodeIdx{PeerIdx: 0, ShareIdx: 1}
	noOverrides := func(core.PubKey) string { return "" }

	t.Run("builder urls", func(t *testing.T) {
		dir := t.TempDir()
		conf := Config{
			LockFile:                   filepath.Join(dir, "cluster-lock.json"),
			BuilderAPI:                 true,
			BuilderURLs:                []string{"https://builder1.example.com", "https://builder2.example.com"},
			BuilderMinBid:              1_000_000_000,
			BuilderBoostFactor:         90,
			BuilderMaxExecutionPayment: 2_000_000_000,
			ProposerGasLimit:           200_000_000,
		}

		created, err := writeProposerConfigFile(conf, &lock, nodeIdx, noOverrides)
		require.NoError(t, err)
		require.True(t, created)

		b, err := os.ReadFile(filepath.Join(dir, proposerConfigDir, proposerConfigFilename))
		require.NoError(t, err)

		var config proposerConfigJSON

		require.NoError(t, json.Unmarshal(b, &config))
		require.EqualValues(t, 1, config.Version)

		// A uniform cluster emits no per-validator entries, the default covers all.
		require.Empty(t, config.ProposerConfig)
		require.Equal(t, "200000000", config.DefaultConfig.GasLimit)

		// The builder configuration is only emitted on the default config, with the
		// shared values at the builder level and entries carrying no overrides.
		require.NotNil(t, config.DefaultConfig.Builder)
		require.Equal(t, "1000000000", config.DefaultConfig.Builder.MinBid)
		require.Equal(t, "90", config.DefaultConfig.Builder.BuilderBoostFactor)
		require.Equal(t, "2000000000", config.DefaultConfig.Builder.MaxExecutionPayment)
		require.Equal(t, []builderEntryJSON{
			{URL: "https://builder1.example.com"},
			{URL: "https://builder2.example.com"},
		}, config.DefaultConfig.Builder.Builders)
	})

	t.Run("no builder urls", func(t *testing.T) {
		dir := t.TempDir()
		conf := Config{
			LockFile:      filepath.Join(dir, "cluster-lock.json"),
			BuilderMinBid: 1, // Inert without builder URLs (the flags reject this combination).
		}

		created, err := writeProposerConfigFile(conf, &lock, nodeIdx, noOverrides)
		require.NoError(t, err)
		require.True(t, created)

		b, err := os.ReadFile(filepath.Join(dir, proposerConfigDir, proposerConfigFilename))
		require.NoError(t, err)

		var config proposerConfigJSON

		require.NoError(t, json.Unmarshal(b, &config))
		require.EqualValues(t, 1, config.Version)
		require.Nil(t, config.DefaultConfig.Builder)
		require.NotContains(t, string(b), "min_bid")
	})
}

func TestProposerConfigMatches(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 1, 4, 4, 0, rand.New(rand.NewSource(0)))

	nodeIdx := cluster.NodeIdx{PeerIdx: 0, ShareIdx: 1}
	noOverrides := func(core.PubKey) string { return "" }

	dir := t.TempDir()
	path := filepath.Join(dir, proposerConfigDir, proposerConfigFilename)

	newConf := func(builderURLs ...string) Config {
		return Config{
			LockFile:           filepath.Join(dir, "cluster-lock.json"),
			BuilderAPI:         true,
			BuilderURLs:        builderURLs,
			BuilderBoostFactor: 90,
			ProposerGasLimit:   200_000_000,
		}
	}

	conf := newConf("https://builder1.example.com")

	created, err := writeProposerConfigFile(conf, &lock, nodeIdx, noOverrides)
	require.NoError(t, err)
	require.True(t, created)

	b, err := os.ReadFile(path)
	require.NoError(t, err)

	builderMatches, gasMatches, err := proposerConfigMatches(conf, path)
	require.NoError(t, err)
	require.True(t, builderMatches)
	require.True(t, gasMatches)

	// Changed builder URLs, builder flags or no builder URLs differ, and leave the file as it is.
	changedBoost := conf
	changedBoost.BuilderBoostFactor = 100

	for _, changed := range []Config{newConf("https://builder2.example.com"), changedBoost, newConf()} {
		created, err = writeProposerConfigFile(changed, &lock, nodeIdx, noOverrides)
		require.NoError(t, err)
		require.False(t, created)

		builderMatches, gasMatches, err = proposerConfigMatches(changed, path)
		require.NoError(t, err)
		require.False(t, builderMatches)
		require.True(t, gasMatches)
	}

	// A changed proposer gas limit differs, and leaves the file as it is.
	changedGas := conf
	changedGas.ProposerGasLimit = 60_000_000

	created, err = writeProposerConfigFile(changedGas, &lock, nodeIdx, noOverrides)
	require.NoError(t, err)
	require.False(t, created)

	builderMatches, gasMatches, err = proposerConfigMatches(changedGas, path)
	require.NoError(t, err)
	require.True(t, builderMatches)
	require.False(t, gasMatches)

	unchanged, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, b, unchanged)

	// A file that isn't a proposer config is an error.
	require.NoError(t, os.WriteFile(path, []byte("operator managed"), 0o644))

	_, _, err = proposerConfigMatches(conf, path)
	require.ErrorContains(t, err, "decode proposer config file")
}
