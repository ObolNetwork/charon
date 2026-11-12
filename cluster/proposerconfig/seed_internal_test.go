// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package proposerconfig

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
)

func TestSeedValidate(t *testing.T) {
	valid := Seed{GasLimit: DefaultGasLimit, BuilderBoostFactor: DefaultBuilderBoostFactor}
	withURL := func(s Seed) Seed {
		s.BuilderURLs = []string{"https://builder.example"}
		return s
	}

	boostSet := func(s Seed) Seed {
		s.NonDefault = []string{"proposer-config-builder-boost-factor"}
		return s
	}

	require.NoError(t, valid.Validate())
	require.NoError(t, boostSet(withURL(valid)).Validate())

	const withoutURLs = "proposer-config-builder-min-bid, proposer-config-builder-boost-factor and " +
		"proposer-config-builder-max-execution-payment require proposer-config-builder-urls"

	tests := []struct {
		name   string
		seed   Seed
		errMsg string
	}{
		{"zero gas limit", Seed{BuilderBoostFactor: 100}, "proposer-config-gas-limit must be greater than 0"},
		{"zero boost factor", Seed{GasLimit: 1}, "proposer-config-builder-boost-factor must be greater than 0"},
		{"min bid without urls", Seed{GasLimit: 1, BuilderBoostFactor: 100, BuilderMinBid: 1}, withoutURLs},
		{"max payment without urls", Seed{GasLimit: 1, BuilderBoostFactor: 100, BuilderMaxExecutionPayment: 1}, withoutURLs},
		{"boost set without urls", boostSet(valid), withoutURLs},
		{"non-http url", Seed{GasLimit: 1, BuilderBoostFactor: 100, BuilderURLs: []string{"ftp://x"}}, "proposer-config-builder-urls entry is not a valid http(s) URL"},
		{"duplicate url", Seed{GasLimit: 1, BuilderBoostFactor: 100, BuilderURLs: []string{"https://a.example", "https://b.example", "https://a.example"}}, "proposer-config-builder-urls entry is duplicated"},
		{"long url", Seed{GasLimit: 1, BuilderBoostFactor: 100, BuilderURLs: []string{"https://" + strings.Repeat("a", core.MaxBuilderURLSize)}}, "proposer-config-builder-urls entry is longer than the maximum"},
		{"unresolved file", Seed{GasLimit: 1, BuilderBoostFactor: 100, File: "seed.json"}, "proposer config seed file not resolved"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorContains(t, tt.seed.Validate(), tt.errMsg)
		})
	}
}

func TestSeedBuilder(t *testing.T) {
	require.Nil(t, Seed{GasLimit: 1}.Builder())

	b := Seed{BuilderURLs: []string{"https://a.example"}, BuilderMinBid: 2, BuilderBoostFactor: 110, BuilderMaxExecutionPayment: 3}.Builder()
	require.Equal(t, &Builder{
		MinBid: "2", BuilderBoostFactor: "110", MaxExecutionPayment: "3",
		Builders: []BuilderEntry{{URL: "https://a.example"}},
	}, b)
}

func TestParseSeed(t *testing.T) {
	const (
		builders   = `"builders":[{"url":"https://a.example.com"},{"url":"https://b.example.com"}]`
		noBuilders = `"builder":{"min_bid":"0","builder_boost_factor":"100","max_execution_payment":"0","builders":[]}`
	)

	tests := []struct {
		name        string
		json        string
		want        Seed
		errContains string
	}{
		{
			name: "builders",
			json: `{"version":"v1.0.0","default_config":{"gas_limit":"60000000","builder":{"min_bid":"1","builder_boost_factor":"90","max_execution_payment":"2",` +
				builders + `}}}`,
			want: Seed{
				GasLimit: 60_000_000, BuilderURLs: []string{"https://a.example.com", "https://b.example.com"},
				BuilderMinBid: 1, BuilderBoostFactor: 90, BuilderMaxExecutionPayment: 2,
			},
		},
		{
			name: "no builders",
			json: `{"version":"v1.0.0","default_config":{"gas_limit":"60000000",` + noBuilders + `}}`,
			want: Seed{GasLimit: 60_000_000, BuilderBoostFactor: DefaultBuilderBoostFactor},
		},
		{name: "missing version", json: `{"default_config":{"gas_limit":"1",` + noBuilders + `}}`, errContains: "version"},
		{name: "other major", json: `{"version":"v2.0.0","default_config":{"gas_limit":"1",` + noBuilders + `}}`, errContains: "version"},
		{name: "numeric gas limit", json: `{"version":"v1.0.0","default_config":{"gas_limit":60000000,` + noBuilders + `}}`, errContains: "gas_limit"},
		{name: "unparsable gas limit", json: `{"version":"v1.0.0","default_config":{"gas_limit":"60M",` + noBuilders + `}}`, errContains: "gas_limit"},
		{name: "empty gas limit", json: `{"version":"v1.0.0","default_config":{"gas_limit":"",` + noBuilders + `}}`, errContains: "gas_limit"},
		{
			name:        "negative builder value",
			json:        `{"version":"v1.0.0","default_config":{"gas_limit":"1","builder":{"min_bid":"-1","builder_boost_factor":"100","max_execution_payment":"0",` + builders + `}}}`,
			errContains: "default_config.builder.min_bid",
		},
		{name: "fee recipient", json: `{"version":"v1.0.0","default_config":{"gas_limit":"1","fee_recipient":"0x01",` + noBuilders + `}}`, errContains: "fee_recipient"},
		{name: "proposer config", json: `{"version":"v1.0.0","default_config":{"gas_limit":"1",` + noBuilders + `},"proposer_config":{}}`, errContains: "proposer_config"},
		{name: "unknown field", json: `{"version":"v1.0.0","default_config":{"gas_limit":"1","gas_limits":"2",` + noBuilders + `}}`, errContains: "gas_limits"},
		{
			name:        "builder entry override",
			json:        `{"version":"v1.0.0","default_config":{"gas_limit":"1","builder":{"builders":[{"url":"https://a.example.com","min_bid":"1"}]}}}`,
			errContains: "min_bid",
		},
		{name: "trailing data", json: `{"version":"v1.0.0","default_config":{"gas_limit":"1",` + noBuilders + `}}{}`, errContains: "trailing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSeed([]byte(tt.json))
			if tt.errContains != "" {
				require.ErrorContains(t, err, tt.errContains)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}

	t.Run("missing values rejected by validate", func(t *testing.T) {
		seed, err := ParseSeed([]byte(`{"version":"v1.0.0","default_config":{"gas_limit":"1"}}`))
		require.NoError(t, err)
		require.ErrorContains(t, seed.Validate(), "proposer-config-builder-boost-factor must be greater than 0")
	})
}

func TestMarshalSeed(t *testing.T) {
	for _, seed := range []Seed{
		{GasLimit: DefaultGasLimit, BuilderBoostFactor: DefaultBuilderBoostFactor},
		{
			GasLimit: 60_000_000, BuilderURLs: []string{"https://a.example.com", "https://b.example.com"},
			BuilderMinBid: 1, BuilderBoostFactor: 90, BuilderMaxExecutionPayment: 2,
		},
	} {
		b, err := MarshalSeed(seed)
		require.NoError(t, err)

		got, err := ParseSeed(b)
		require.NoError(t, err)
		require.Equal(t, seed, got)
	}

	// Every value is written, the builder block included when there are no builders.
	b, err := MarshalSeed(Seed{GasLimit: DefaultGasLimit, BuilderBoostFactor: DefaultBuilderBoostFactor})
	require.NoError(t, err)
	require.JSONEq(t, `{"version":"v1.0.0","default_config":{"gas_limit":"200000000",`+
		`"builder":{"min_bid":"0","builder_boost_factor":"100","max_execution_payment":"0","builders":[]}}}`, string(b))
}

func TestParseSeedExample(t *testing.T) {
	b, err := os.ReadFile("../examples/proposer-config-seed-000.json")
	require.NoError(t, err)

	seed, err := ParseSeed(b)
	require.NoError(t, err)
	require.NoError(t, seed.Validate())
	require.Len(t, seed.BuilderURLs, 2)

	// The DKG agrees on the gas limit and builder only, so operators passing the example file and operators passing
	// the equal flags agree.
	flags := Seed{
		GasLimit:           DefaultGasLimit,
		BuilderURLs:        []string{"https://builder-a.example", "https://builder-b.example"},
		BuilderBoostFactor: DefaultBuilderBoostFactor,
	}
	require.Equal(t, flags.GasLimit, seed.GasLimit)
	require.Equal(t, flags.Builder(), seed.Builder())
}
