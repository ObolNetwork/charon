// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

func TestVerifyDepositAmounts(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		err := VerifyDepositAmounts(nil)

		require.NoError(t, err)
	})

	t.Run("valid amounts", func(t *testing.T) {
		amounts := []eth2p0.Gwei{
			eth2p0.Gwei(16000000000),
			eth2p0.Gwei(16000000000),
		}

		err := VerifyDepositAmounts(amounts)

		require.NoError(t, err)
	})

	t.Run("each amount is greater than 1ETH", func(t *testing.T) {
		amounts := []eth2p0.Gwei{
			eth2p0.Gwei(500000000),   // 0.5ETH
			eth2p0.Gwei(31500000000), // 31.5ETH
		}

		err := VerifyDepositAmounts(amounts)

		require.ErrorContains(t, err, "each partial deposit amount must be greater than 1ETH")
	})

	t.Run("total sum is 32ETH", func(t *testing.T) {
		amounts := []eth2p0.Gwei{
			eth2p0.Gwei(1000000000),
			eth2p0.Gwei(32000000000),
		}

		err := VerifyDepositAmounts(amounts)

		require.ErrorContains(t, err, "sum of partial deposit amounts must sum up to 32ETH")
	})
}

func TestConvertIntAmountsToGwei(t *testing.T) {
	t.Run("nil slice", func(t *testing.T) {
		slice := DepositAmountsFromIntSlice(nil)

		require.Nil(t, slice)
	})

	t.Run("values", func(t *testing.T) {
		slice := DepositAmountsFromIntSlice([]int{
			1000000000,
			5000000000,
		})

		require.Equal(t, []eth2p0.Gwei{
			eth2p0.Gwei(1000000000),
			eth2p0.Gwei(5000000000),
		}, slice)
	})
}
