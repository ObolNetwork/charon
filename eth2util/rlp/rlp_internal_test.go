// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package rlp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeLength(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		items := []byte{0xb8, 0x01, 0x0a}
		offset, length, err := decodeLength(items)
		require.NoError(t, err)
		require.Equal(t, 2, offset)
		require.Equal(t, 1, length)
	})

	t.Run("prefix absent", func(t *testing.T) {
		_, _, err := decodeLength(nil)
		require.ErrorContains(t, err, "input too short")
	})

	t.Run("prefix provided but length absent", func(t *testing.T) {
		items := []byte{0xbf}
		_, _, err := decodeLength(items)
		require.ErrorContains(t, err, "input too short")
	})

	t.Run("overflow", func(t *testing.T) {
		items := []byte{0xb8, 0x10, 0x0a}
		_, _, err := decodeLength(items)
		require.ErrorContains(t, err, "overflow")
	})
}
