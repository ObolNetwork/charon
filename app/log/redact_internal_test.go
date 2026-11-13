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
		{"https://user:p@ss@bn.example.com/eth/v1", "https://user:xxxxx@bn.example.com/eth/v1"},
		{"operator@example.com", "operator@example.com"},
		{"bn.example.com/eth/v1", "bn.example.com/eth/v1"},
	}
	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			require.Equal(t, test.want, RedactURL(test.in, false))
		})
	}
}

// TestRedactURLUnparsed covers URLs that url.Parse rejects, which must not be returned as they are.
func TestRedactURLUnparsed(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no scheme", "user:s3cret@builder.example.com/apikey123", "xxxxx@builder.example.com/xxxxx"},
		{"no scheme no path", "user:s3cret@host", "xxxxx@host"},
		{"percent in password", "https://user:pa%ss@builder.example.com", "https://xxxxx@builder.example.com"},
		{"slash in password", "https://user:pa/ss@builder.example.com", "https://xxxxx@builder.example.com"},
		{"space in password", "https://user:pa ss@builder.example.com", "https://xxxxx@builder.example.com"},
		{"hash in password", "https://user:p#ss@builder.example.com", "https://xxxxx@builder.example.com"},
		{"trailing newline", "https://user:s3cret@builder.example.com/key\n", "https://xxxxx@builder.example.com/xxxxx"},
		{"leading space", " https://user:s3cret@builder.example.com/key", " https://xxxxx@builder.example.com/xxxxx"},
		{"ipv6 zone", "https://user:s3cret@[fe80::1%eth0]/key", "https://xxxxx@[fe80::1%eth0]/xxxxx"},
		{"invalid port", "https://user:s3cret@builder.example.com:80a/key?token=t", "https://xxxxx@builder.example.com:80a/xxxxx"},
		{"invalid port no credentials", "https://builder.example.com:80a/key", "https://builder.example.com:80a/xxxxx"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, RedactURL(test.in, false))
			require.Equal(t, test.want, RedactURL(test.in, true))
		})
	}

	// Without a scheme or credentials a path is only masked where paths are.
	require.Equal(t, "builder.example.com/xxxxx", RedactURL("builder.example.com/apikey123", true))
	require.Equal(t, "builder.example.com/apikey123", RedactURL("builder.example.com/apikey123", false))
}

// TestRedactURLMisreadCredentials covers URLs that parse without credentials but hold an "@" after the host, as
// with an unescaped password: the credentials end at the last "@" and the rest is redacted as for any parsed URL.
func TestRedactURLMisreadCredentials(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		want       string
		wantMasked string
	}{
		{
			name:       "slash in password",
			in:         "https://user:12/34@builder.example.com",
			want:       "https://xxxxx@builder.example.com",
			wantMasked: "https://xxxxx@builder.example.com",
		},
		{
			name:       "hash in password",
			in:         "https://user:12#34@builder.example.com/eth/v1?slot=5&token=t",
			want:       "https://xxxxx@builder.example.com/eth/v1?slot=5&token=xxxxx",
			wantMasked: "https://xxxxx@builder.example.com/xxxxx?slot=5&token=xxxxx",
		},
		{
			name:       "slash and question mark in password",
			in:         "https://user:12/3?4@builder.example.com/eth",
			want:       "https://xxxxx@builder.example.com/eth",
			wantMasked: "https://xxxxx@builder.example.com/xxxxx",
		},
		{
			name:       "at in query",
			in:         "https://user:12/34@builder.example.com/eth?email=a@b.com",
			want:       "https://xxxxx@b.com",
			wantMasked: "https://xxxxx@b.com",
		},
		{
			name:       "no credentials and at in query",
			in:         "https://builder.example.com/eth?email=a@b.com",
			want:       "https://xxxxx@b.com",
			wantMasked: "https://xxxxx@b.com",
		},
		{
			name:       "no credentials and at in path",
			in:         "https://builder.example.com/users/@operator",
			want:       "https://xxxxx@operator",
			wantMasked: "https://xxxxx@operator",
		},
		{
			name:       "invalid after the credentials",
			in:         "https://user:12/34@builder.example.com:80a/key",
			want:       "https://xxxxx@builder.example.com:80a/xxxxx",
			wantMasked: "https://xxxxx@builder.example.com:80a/xxxxx",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, RedactURL(test.in, false))
			require.Equal(t, test.wantMasked, RedactURL(test.in, true))
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
