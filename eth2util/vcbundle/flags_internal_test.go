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
		},
		{
			client: Prysm,
			want:   []string{"--distributed", "--enable-beacon-rest-api"},
		},
		{
			client:      Lodestar,
			want:        []string{"--distributed", "--payloadLocal=true", "--builder.selection=maxprofit"},
			wantBuilder: []string{"--allowDangerousTrustedPayments"},
		},
		{
			client: Nimbus,
			want:   []string{"--distributed", "--doppelganger-detection=false"},
			wantBuilder: []string{
				"--payload-builder=true", "--payload-builder-url=https://builder-a.example.com", "--payload-builder-url=https://builder-b.example.com",
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
			require.Equal(t, test.want, vcFlags(test.client, testConfig(false)))
			require.Equal(t, append(test.want, test.wantBuilder...), vcFlags(test.client, testConfig(true)))
		})
	}

	t.Run("lodestar zero max execution payment", func(t *testing.T) {
		cfg := testConfig(true)
		cfg.DefaultConfig.Builder.MaxExecutionPayment = "0"

		require.Equal(t, []string{"--distributed", "--payloadLocal=true", "--builder.selection=maxprofit"}, vcFlags(Lodestar, cfg))
	})
}

func TestRenderFlags(t *testing.T) {
	require.Empty(t, renderFlags(nil))
	require.Equal(t, "--a=1\n--b\n", string(renderFlags([]string{"--a=1", "--b"})))
}
