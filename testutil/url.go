// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package testutil

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func MustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()

	url, err := url.Parse(rawURL)
	require.NoError(t, err)

	return url
}

func MustParseRequestURI(t *testing.T, rawURL string) *url.URL {
	t.Helper()

	url, err := url.ParseRequestURI(rawURL)
	require.NoError(t, err)

	return url
}
