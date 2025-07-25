// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app"
)

func TestHex7(t *testing.T) {
	someHash, err := hex.DecodeString("433287d255abf237992d2279af5b1a1bb2c3d7124c97906edd848ebbb541a1c7")
	require.NoError(t, err)

	tests := []struct {
		input    []byte
		expected string
	}{
		{someHash, "433287d"},
		{[]byte("aaa"), "616161"},
		{[]byte(""), ""},
	}

	for _, test := range tests {
		result := app.Hex7(test.input)
		require.Equal(t, test.expected, result, "Hex7 should return the first 7 hex characters of the input")
	}
}
