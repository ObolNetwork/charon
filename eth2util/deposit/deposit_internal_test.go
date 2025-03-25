// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package deposit

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWithdrawalCredentials(t *testing.T) {
	const addr = "c0404ed740a69d11201f5ed297c5732f562c6e4e"

	t.Run("standard", func(t *testing.T) {
		expectedWithdrawalCreds := "010000000000000000000000" + addr
		creds, err := withdrawalCredsFromAddr("0x"+addr, false)
		require.NoError(t, err)

		credsHex := hex.EncodeToString(creds[:])

		require.Equal(t, expectedWithdrawalCreds, credsHex)
	})

	t.Run("compounding", func(t *testing.T) {
		expectedWithdrawalCreds := "020000000000000000000000" + addr
		creds, err := withdrawalCredsFromAddr("0x"+addr, true)
		require.NoError(t, err)

		credsHex := hex.EncodeToString(creds[:])

		require.Equal(t, expectedWithdrawalCreds, credsHex)
	})
}
