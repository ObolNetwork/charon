// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_fallbackClient(t *testing.T) {
	// 4 clients
	f := NewFallbackClient(1*time.Second, [4]byte{1, 2, 3, 4}, []string{
		"https://google.com",
		"https://x.com",
		"https://google.com",
		"https://x.com",
	})

	// pick four
	for range 4 {
		_, err := f.pick()
		require.NoError(t, err)
	}

	// pick fifth, error
	_, err := f.pick()
	require.ErrorContains(t, err, "all fallback clients have been taken")

	// put one back
	f.place()

	// pick again, no error
	_, err = f.pick()
	require.NoError(t, err)
}

func Test_fallbackClient_noneSpecified(t *testing.T) {
	// 4 clients
	f := NewFallbackClient(1*time.Second, [4]byte{1, 2, 3, 4}, []string{})

	// pick one, error
	_, err := f.pick()
	require.ErrorContains(t, err, "all fallback clients have been taken")

	// place one, error
	f.place()
}
