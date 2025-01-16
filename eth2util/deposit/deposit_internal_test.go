// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package deposit

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWithdrawalCredentials(t *testing.T) {
	expectedWithdrawalCreds := "020000000000000000000000c0404ed740a69d11201f5ed297c5732f562c6e4e"
	creds, err := withdrawalCredsFromAddr("0xc0404ed740a69d11201f5ed297c5732f562c6e4e")
	require.NoError(t, err)

	credsHex := hex.EncodeToString(creds[:])

	require.Equal(t, expectedWithdrawalCreds, credsHex)
}
