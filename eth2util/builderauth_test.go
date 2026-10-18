// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
)

// The vectors mirror Lighthouse's default auth data tests at commit
// c8ddac7b79d49812283873eb6625149ef0d27f95 (common/builder_types/src/builder_url.rs), so charon
// derives the same bytes as the validator clients signing the builder request auths.

func TestBuilderAuthDataIgnoresURLSpelling(t *testing.T) {
	for _, url := range []string{
		"https://builder.example.com",
		"https://builder.example.com/",
		"HTTPS://Builder.Example.com:443/bids?x=1#fragment",
		"https://user:pw@builder.example.com:8080/",
		"https://Builder.Example.com\r\n",
		"https:/\t/Buil\tder.Example.com/",
	} {
		data, err := eth2util.BuilderAuthData(url)
		require.NoError(t, err, url)
		require.Equal(t, []byte("builder.example.com"), data, url)
	}
}

func TestBuilderAuthDataHostnames(t *testing.T) {
	for _, test := range []struct {
		url      string
		expected string
	}{
		{"https://10.0.0.5:18550/eth/v1/builder", "10.0.0.5"},
		{"https://[0:0:0:0:0:0:0:1]:8443/", "[::1]"},
		{"https://[::ffff:192.0.2.1]/", "[::ffff:c000:201]"},
		{"https://[2001:0DB8:0:0:1:0:0:1]/", "[2001:db8::1:0:0:1]"},
		{"https://XN--BCHER-KVA.example/", "xn--bcher-kva.example"},
		{"https://builder.example/\u8def\u5f91", "builder.example"}, // Non-ASCII path, hostname unaffected.
		{"http://127.1/", "127.1"},
		{"http://0177.0.0.1/", "0177.0.0.1"},
		{"https://%65XAMPLE.com/", "%65xample.com"},
	} {
		data, err := eth2util.BuilderAuthData(test.url)
		require.NoError(t, err, test.url)
		require.Equal(t, test.expected, string(data), test.url)
	}
}

func TestBuilderAuthDataRequiresASCIIHostname(t *testing.T) {
	for _, url := range []string{
		"",
		"not a URL",
		"mailto:builder@example.com",
		"https://bücher.example/",
		"https:///path",
	} {
		_, err := eth2util.BuilderAuthData(url)
		require.Error(t, err, url)
	}
}
