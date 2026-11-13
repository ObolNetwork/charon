// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package proposerconfig

import (
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
