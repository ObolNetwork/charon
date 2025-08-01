// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package relay

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app"
)

func TestHex7(t *testing.T) {
	// byte(97) = 0x(61)
	t.Run("more than 7 characters", func(t *testing.T) {
		r := app.Hex7([]byte("aaaa")) // []byte{97, 97, 97, 97} = hex_string("61616161")
		require.Equal(t, r, "6161616")
	})

	t.Run("less than 7 characters", func(t *testing.T) {
		r := app.Hex7([]byte("aaa")) // []byte{97, 97, 97} = hex_string("616161")
		require.Equal(t, r, "616161")
	})
}
