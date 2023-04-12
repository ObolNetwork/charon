// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package deposit_test

import (
	"encoding/hex"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/deposit"
	tblsv2 "github.com/obolnetwork/charon/tbls"
	tblsconv2 "github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -run=TestMarshalDepositData -update -clean

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

		msg, err := deposit.NewMessage(pk, withdrawalAddrs[i])
		require.NoError(t, err)

		sigRoot, err := deposit.GetMessageSigningRoot(msg, network)
		require.NoError(t, err)

		sig, err := tblsv2.Sign(sk, sigRoot[:])
		require.NoError(t, err)

		datas = append(datas, eth2p0.DepositData{
			PublicKey:             msg.PublicKey,
			WithdrawalCredentials: msg.WithdrawalCredentials,
			Amount:                msg.Amount,
			Signature:             tblsconv2.SigToETH2(sig),
		})
	}

	actual, err := deposit.MarshalDepositData(datas, network)
	require.NoError(t, err)

	testutil.RequireGoldenBytes(t, actual)
}

// Get the private and public keys in appropriate format for the test.
func GetKeys(t *testing.T, privKey string) (tblsv2.PrivateKey, eth2p0.BLSPubKey) {
	t.Helper()

	privKeyBytes, err := hex.DecodeString(privKey)
	require.NoError(t, err)

	sk, err := tblsconv2.PrivkeyFromBytes(privKeyBytes)
	require.NoError(t, err)

	pk, err := tblsv2.SecretToPublicKey(sk)
	require.NoError(t, err)

	pubkey, err := tblsconv2.PubkeyToETH2(pk)
	require.NoError(t, err)

	return sk, pubkey
}
