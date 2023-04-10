// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package relay

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClusterHash(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		r, err := clusterHash([]byte("aaaa")) // []byte{97, 97, 97, 97}
		require.NoError(t, err)
		// Since byte(97) = hex(61), []byte{97, 97, 97, 97} = hex_string("61616161")
		require.Equal(t, r, "6161616")
	})

	t.Run("insufficient characters", func(t *testing.T) {
		_, err := clusterHash(nil)
		require.ErrorContains(t, err, "insufficient characters in lockhash")
	})
}
