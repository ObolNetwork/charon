// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package deposit_test

import (
	"encoding/hex"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -run=TestMarshalDepositData -update -clean

func TestNewMessage(t *testing.T) {
	const privKey = "01477d4bfbbcebe1fef8d4d6f624ecbb6e3178558bb1b0d6286c816c66842a6d"
	const addr = "0x321dcb529f3945bc94fecea9d3bc5caf35253b94"
	amount := deposit.MaxValidatorAmount
	_, pubKey := GetKeys(t, privKey)

	msg, err := deposit.NewMessage(pubKey, addr, amount)

	require.NoError(t, err)
	require.Equal(t, pubKey, msg.PublicKey)
	require.Equal(t, amount, msg.Amount)

	t.Run("amount below minimum", func(t *testing.T) {
		_, err := deposit.NewMessage(pubKey, addr, deposit.MinValidatorAmount-1)

		require.ErrorContains(t, err, "deposit message minimum amount must be >= 1ETH")
	})

	t.Run("amount above maximum", func(t *testing.T) {
		_, err := deposit.NewMessage(pubKey, addr, deposit.MaxValidatorAmount+1)

		require.ErrorContains(t, err, "deposit message maximum amount must <= 32ETH")
	})
}

func TestMarshalDepositData(t *testing.T) {
	privKeys := []string{
		"01477d4bfbbcebe1fef8d4d6f624ecbb6e3178558bb1b0d6286c816c66842a6d",
		"5b77c0f0ef7c4ddc123d55b8bd93daeefbd7116764a941c0061a496649e145b5",
		"1dabcbfc9258f0f28606bf9e3b1c9f06d15a6e4eb0fbc28a43835eaaed7623fc",
		"002ff4fd29d3deb6de9f5d115182a49c618c97acaa365ad66a0b240bd825c4ff",
	}
	withdrawalAddrs := []string{
		"0x321dcb529f3945bc94fecea9d3bc5caf35253b94",
		"0x08ef6a66a4f315aa250d2e748de0bfe5a6121096",
		"0x05f9f73f74c205f2b9267c04296e3069767531fb",
		"0x67f5df029ae8d3f941abef0bec6462a6b4e4b522",
	}

	var (
		datas   []eth2p0.DepositData
		network = eth2util.Goerli.Name
	)
	for i := 0; i < len(privKeys); i++ {
		sk, pk := GetKeys(t, privKeys[i])

		msg, err := deposit.NewMessage(pk, withdrawalAddrs[i], deposit.MaxValidatorAmount)
		require.NoError(t, err)

		sigRoot, err := deposit.GetMessageSigningRoot(msg, network)
		require.NoError(t, err)

		sig, err := tbls.Sign(sk, sigRoot[:])
		require.NoError(t, err)

		datas = append(datas, eth2p0.DepositData{
			PublicKey:             msg.PublicKey,
			WithdrawalCredentials: msg.WithdrawalCredentials,
			Amount:                msg.Amount,
			Signature:             tblsconv.SigToETH2(sig),
		})
	}

	actual, err := deposit.MarshalDepositData(datas, network)
	require.NoError(t, err)

	testutil.RequireGoldenBytes(t, actual)
}

// Get the private and public keys in appropriate format for the test.
func GetKeys(t *testing.T, privKey string) (tbls.PrivateKey, eth2p0.BLSPubKey) {
	t.Helper()

	privKeyBytes, err := hex.DecodeString(privKey)
	require.NoError(t, err)

	sk, err := tblsconv.PrivkeyFromBytes(privKeyBytes)
	require.NoError(t, err)

	pk, err := tbls.SecretToPublicKey(sk)
	require.NoError(t, err)

	pubkey, err := tblsconv.PubkeyToETH2(pk)
	require.NoError(t, err)

	return sk, pubkey
}

func TestVerifyDepositAmounts(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		err := deposit.VerifyDepositAmounts(nil)

		require.NoError(t, err)
	})

	t.Run("valid amounts", func(t *testing.T) {
		amounts := []eth2p0.Gwei{
			eth2p0.Gwei(16000000000),
			eth2p0.Gwei(16000000000),
		}

		err := deposit.VerifyDepositAmounts(amounts)

		require.NoError(t, err)
	})

	t.Run("each amount is greater than 1ETH", func(t *testing.T) {
		amounts := []eth2p0.Gwei{
			eth2p0.Gwei(500000000),   // 0.5ETH
			eth2p0.Gwei(31500000000), // 31.5ETH
		}

		err := deposit.VerifyDepositAmounts(amounts)

		require.ErrorContains(t, err, "each partial deposit amount must be greater than 1ETH")
	})

	t.Run("total sum is 32ETH", func(t *testing.T) {
		amounts := []eth2p0.Gwei{
			eth2p0.Gwei(1000000000),
			eth2p0.Gwei(32000000000),
		}

		err := deposit.VerifyDepositAmounts(amounts)

		require.ErrorContains(t, err, "sum of partial deposit amounts must sum up to 32ETH")
	})
}

func TestEthsToGweis(t *testing.T) {
	t.Run("nil slice", func(t *testing.T) {
		slice := deposit.EthsToGweis(nil)

		require.Nil(t, slice)
	})

	t.Run("values", func(t *testing.T) {
		slice := deposit.EthsToGweis([]int{1, 5})

		require.Equal(t, []eth2p0.Gwei{
			eth2p0.Gwei(1000000000),
			eth2p0.Gwei(5000000000),
		}, slice)
	})
}
