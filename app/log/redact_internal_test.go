// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package log

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
)

func TestRedactURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://user:secret@bn.example.com:5052", "https://user:xxxxx@bn.example.com:5052"},
		{"http://:secret@lighthouse:5052/eth/v1?x=1", "http://:xxxxx@lighthouse:5052/eth/v1?x=1"},
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
			require.Equal(t, test.want, RedactURL(test.in, false))
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

	require.Equal(t, []string{"https://a.example.com/xxxxx", "http://lighthouse:5052"},
		RedactURLs([]string{"https://a.example.com/v2/key", "http://lighthouse:5052"}, true))
}

func TestRedactURLError(t *testing.T) {
	uerr := &url.Error{Op: "Post", URL: "https://el.example.com/v2/abcDEF123ghiJKL456mnoPQR789", Err: errors.New("timeout")}
	err := errors.Wrap(RedactURLError(uerr), "call")

	require.NotContains(t, err.Error(), "abcDEF123")
	require.Contains(t, err.Error(), "https://el.example.com/v2/xxxxx")
	require.ErrorIs(t, err, uerr)
	require.NoError(t, RedactURLError(nil))
}
