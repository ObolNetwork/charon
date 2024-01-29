// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	"encoding/json"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"
)

func TestDepositJSON(t *testing.T) {
	deposit := RandomDepositData()
	depositJSON := depositDataToJSON(deposit)

	eth2Deposit := &eth2p0.DepositData{
		PublicKey:             *(*eth2p0.BLSPubKey)(deposit.PubKey),
		WithdrawalCredentials: deposit.WithdrawalCredentials,
		Amount:                eth2p0.Gwei(deposit.Amount),
		Signature:             *(*eth2p0.BLSSignature)(deposit.Signature),
	}

	b1, err := json.MarshalIndent(depositJSON, "", " ")
	require.NoError(t, err)
	b2, err := json.MarshalIndent(eth2Deposit, "", " ")
	require.NoError(t, err)

	require.Equal(t, b1, b2)
}

func TestDepositArrayJSON(t *testing.T) {
	dd := []DepositData{
		RandomDepositData(),
		RandomDepositData(),
		RandomDepositData(),
	}

	json := depositDataArrayToJSON(dd)
	dd2 := depositDataArrayFromJSON(json)

	require.Equal(t, dd, dd2)

	t.Run("nil", func(t *testing.T) {
		require.Nil(t, depositDataArrayToJSON(nil))
		require.Nil(t, depositDataArrayFromJSON(nil))
	})
}
