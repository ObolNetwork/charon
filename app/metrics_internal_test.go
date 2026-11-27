// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWithoutUserInfo(t *testing.T) {
	require.Equal(t, "https://relay.example.com", withoutUserInfo("https://0xabc@relay.example.com"))
	require.Equal(t, "https://builder.example.com/path", withoutUserInfo("https://user:secret@builder.example.com/path"))
	require.Equal(t, "http://mev-boost:18550", withoutUserInfo("http://mev-boost:18550"))
	// A URL the auth data accepts but url.Parse rejects must not leak its password.
	require.Equal(t, "invalid", withoutUserInfo("https://user:secret@builder.example.com/%zz"))
}
