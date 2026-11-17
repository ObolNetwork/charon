// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package vcbundle

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/testutil"
)

// testConfig has one validator with its own fee recipient and, optionally, a builder block with two builders.
func testConfig(withBuilder bool) proposerconfig.Config {
	cfg := proposerconfig.Config{
		DefaultConfig: proposerconfig.Settings{FeeRecipient: "0x000000000000000000000000000000000000dead", GasLimit: "60000000"},
		ProposerConfig: map[string]proposerconfig.Settings{
			testPubkeyA: {FeeRecipient: "0x000000000000000000000000000000000000beef"},
		},
	}

	if withBuilder {
		cfg.DefaultConfig.Builder = &proposerconfig.Builder{
			MinBid:              "1",
			BuilderBoostFactor:  "90",
			MaxExecutionPayment: "5",
			Builders: []proposerconfig.BuilderEntry{
				{URL: "https://builder-a.example.com"},
				{URL: "https://builder-b.example.com", MinBid: "2", MaxExecutionPayment: "7"},
			},
		}
	}

	return cfg
}

func TestRenderProposerConfig(t *testing.T) {
	renders := map[string]func(proposerconfig.Config) ([]byte, error){
		"teku":     renderTeku,
		"prysm":    renderPrysm,
		"lodestar": renderLodestar,
	}

	for client, render := range renders {
		for name, withBuilder := range map[string]bool{"builder": true, "no_builder": false} {
			t.Run(client+"_"+name, func(t *testing.T) {
				b, err := render(testConfig(withBuilder))
				require.NoError(t, err)
				testutil.RequireGoldenBytes(t, b)
			})
		}
	}
}

func TestRenderLighthouse(t *testing.T) {
	keystores := []keystoreFile{
		{Pubkey: testPubkeyA, KeystorePath: "/opt/charon/validator_keys/keystore-0.json", PasswordPath: "/opt/charon/validator_keys/keystore-0.txt"},
		{Pubkey: testPubkeyB, KeystorePath: "/opt/charon/validator_keys/keystore-1.json", PasswordPath: "/opt/charon/validator_keys/keystore-1.txt", Index: 1},
	}

	t.Run("definitions", func(t *testing.T) {
		b, err := renderLighthouseDefinitions(testConfig(true), keystores)
		require.NoError(t, err)
		testutil.RequireGoldenBytes(t, b)
	})

	t.Run("definitions without builder", func(t *testing.T) {
		b, err := renderLighthouseDefinitions(testConfig(false), keystores)
		require.NoError(t, err)
		require.Contains(t, string(b), "  builder_proposals: false\n")
		require.NotContains(t, string(b), "builder_proposals: true")
	})

	t.Run("builders", func(t *testing.T) {
		b, err := renderLighthouseBuilders(testConfig(true).DefaultConfig.Builder)
		require.NoError(t, err)
		testutil.RequireGoldenBytes(t, b)
	})

	t.Run("no builders", func(t *testing.T) {
		b, err := renderLighthouseBuilders(nil)
		require.NoError(t, err)
		require.JSONEq(t, `{"min_bid": 0, "builder_boost_factor": 100, "builders": []}`, string(b))
	})

	t.Run("gas limit not a number", func(t *testing.T) {
		cfg := testConfig(false)
		cfg.DefaultConfig.GasLimit = "lots"
		_, err := renderLighthouseDefinitions(cfg, keystores)
		require.ErrorContains(t, err, "parse gas limit")
	})

	t.Run("builder value not a number", func(t *testing.T) {
		builder := *testConfig(true).DefaultConfig.Builder
		builder.MinBid = "x"
		_, err := renderLighthouseBuilders(&builder)
		require.ErrorContains(t, err, "parse min_bid")
	})
}
