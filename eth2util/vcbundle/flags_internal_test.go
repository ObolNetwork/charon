// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package vcbundle

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVCFlags(t *testing.T) {
	tests := []struct {
		client      Client
		want        []string
		wantBuilder []string
	}{
		{
			client: Teku,
			want:   []string{"--Xobol-dvt-integration-enabled=true"},
			wantBuilder: []string{
				"--Xbuilder-urls=https://builder-a.example.com,https://builder-b.example.com",
				"--Xbuilder-min-bid=1", "--Xbuilder-boost-factor=90", "--Xbuilder-max-execution-payment=5",
			},
		},
		{
			client: Prysm,
			want:   []string{"--distributed", "--enable-beacon-rest-api"},
		},
		{
			client:      Lodestar,
			want:        []string{"--distributed", "--payloadLocal=true"},
			wantBuilder: []string{"--builder=true", "--allowDangerousTrustedPayments"},
		},
		{
			client: Nimbus,
			want:   []string{"--distributed", "--doppelganger-detection=false"},
			wantBuilder: []string{
				"--payload-builder=true", "--payload-builder-url=https://builder-a.example.com",
				"--builder-min-bid=1", "--builder-boost-factor=90", "--builder-max-execution-payment=5",
			},
		},
		{
			client: Lighthouse,
			want:   []string{"--distributed"},
		},
	}
	for _, test := range tests {
		t.Run(string(test.client), func(t *testing.T) {
			got, err := vcFlags(t.Context(), test.client, testConfig(false))
			require.NoError(t, err)
			require.Equal(t, test.want, got)

			got, err = vcFlags(t.Context(), test.client, testConfig(true))
			require.NoError(t, err)
			require.Equal(t, append(test.want, test.wantBuilder...), got)
		})
	}

	t.Run("nimbus first builder values", func(t *testing.T) {
		cfg := testConfig(true)
		cfg.DefaultConfig.Builder.Builders[0].MinBid = "3"
		cfg.DefaultConfig.Builder.Builders[0].MaxExecutionPayment = "8"

		got, err := vcFlags(t.Context(), Nimbus, cfg)
		require.NoError(t, err)
		require.Contains(t, got, "--builder-min-bid=3")
		require.Contains(t, got, "--builder-max-execution-payment=8")
		require.Contains(t, got, "--builder-boost-factor=90")
	})

	t.Run("lodestar zero max execution payment", func(t *testing.T) {
		cfg := testConfig(true)
		cfg.DefaultConfig.Builder.MaxExecutionPayment = "0"

		got, err := vcFlags(t.Context(), Lodestar, cfg)
		require.NoError(t, err)
		require.Equal(t, []string{"--distributed", "--payloadLocal=true", "--builder=true"}, got)
	})

	t.Run("teku builder url with comma", func(t *testing.T) {
		cfg := testConfig(true)
		cfg.DefaultConfig.Builder.Builders[1].URL = "https://a.example.com/x,y"

		_, err := vcFlags(t.Context(), Teku, cfg)
		require.ErrorContains(t, err, "builder url contains a comma")
	})
}

func TestRenderFlags(t *testing.T) {
	require.Empty(t, renderFlags(nil))
	require.Equal(t, "--a=1\n--b\n", string(renderFlags([]string{"--a=1", "--b"})))
}
