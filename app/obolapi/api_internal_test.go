// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWithTimeout(t *testing.T) {
	// no timeout = 10s timeout
	oapi, err := New("http://url.com")
	require.NoError(t, err)
	require.Equal(t, defaultTimeout, oapi.reqTimeout)

	// with timeout = timeout specified
	timeout := 1 * time.Minute
	oapi, err = New("http://url.com", WithTimeout(timeout))
	require.NoError(t, err)
	require.Equal(t, timeout, oapi.reqTimeout)
}
