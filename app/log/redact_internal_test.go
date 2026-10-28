// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package log

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

func TestRedactURLs(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://user:secret@bn.example.com:5052", "https://user:xxxxx@bn.example.com:5052"},
		{"http://:secret@lighthouse:5052/eth/v1?x=1", "http://:xxxxx@lighthouse:5052/eth/v1?x=1"},
		{"[http://a:b@one,https://c:d@two]", "[http://a:xxxxx@one,https://c:xxxxx@two]"},
		{`Get "https://user:secret@bn:5052/eth/v1/node/version": EOF`, `Get "https://user:xxxxx@bn:5052/eth/v1/node/version": EOF`},
		{"https://eth-mainnet.g.alchemy.com/v2/abcDEF123ghiJKL456mnoPQR789", "https://eth-mainnet.g.alchemy.com/v2/xxxxx"},
		{"https://bn.example.com/eth/v1/beacon?apikey=secret&x=1", "https://bn.example.com/eth/v1/beacon?apikey=xxxxx&x=1"},
		{"http://bn:5052/eth/v1/validator/attestation_data?slot=12345678&committee_index=3", "http://bn:5052/eth/v1/validator/attestation_data?slot=12345678&committee_index=3"},
		{"http://bn:5052/eth/v3/validator/blocks/123?randao_reveal=0xab12&graffiti=hi", "http://bn:5052/eth/v3/validator/blocks/123?graffiti=xxxxx&randao_reveal=0xab12"},
		{"http://bn:5052/eth/v1/validator/prepare_beacon_proposer", "http://bn:5052/eth/v1/validator/prepare_beacon_proposer"},
		{"https://api.obol.tech/v1/lock/0x0f481bbd06a596cb3ba569b9de0cbfcf822b209c2d6877c98173df986dd3c0ec", "https://api.obol.tech/v1/lock/0x0f481bbd06a596cb3ba569b9de0cbfcf822b209c2d6877c98173df986dd3c0ec"},
		{"https://user@bn.example.com", "https://user@bn.example.com"},
		{"http://lighthouse:5052", "http://lighthouse:5052"},
		{"user:secret@host", "user:secret@host"},
		{"operator@example.com", "operator@example.com"},
	}
	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			require.Equal(t, test.want, redactURLs(test.in))
		})
	}
}

func TestRedactURLMaskPath(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://mainnet.infura.io/v3/0123456789abcdef", "https://mainnet.infura.io/xxxxx"},
		{"https://user:secret@bn.example.com/key?token=t", "https://user:xxxxx@bn.example.com/xxxxx?token=xxxxx"},
		{"http://lighthouse:5052", "http://lighthouse:5052"},
		{"http://lighthouse:5052/", "http://lighthouse:5052/"},
		{"lighthouse:5052", "lighthouse:5052"},
		{"127.0.0.1:3600", "127.0.0.1:3600"},
	}
	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			require.Equal(t, test.want, RedactURL(test.in, true))
		})
	}
}

func TestLogRedactsURLPasswords(t *testing.T) {
	var buf zaptest.Buffer

	ctx := WithLogger(context.Background(), NewConsoleForT(t, &buf))
	ctx = WithCtx(ctx, z.Str("ctx_url", "https://ctx:secret@bn"))
	url := "https://user:secret@bn.example.com"

	Debug(ctx, "debug "+url, z.Str("url", url))
	Info(ctx, "info", z.Any("urls", []string{url}))
	Warn(ctx, "warn", errors.New("dial "+url, z.Str("addr", url)))
	Error(ctx, "error", nil, z.Err(errors.New("dial "+url)))

	require.NotContains(t, buf.String(), "secret")
	require.Contains(t, buf.String(), "https://user:xxxxx@bn.example.com")
	require.Contains(t, buf.String(), "https://ctx:xxxxx@bn")
}
