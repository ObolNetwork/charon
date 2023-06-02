// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package registration_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/registration"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
)

func TestNewMessage(t *testing.T) {
	gasLimit := uint64(30000000)

	timestamp, err := time.Parse("Jan 2, 2006", "Jan 1, 2000")
	require.NoError(t, err)

	pubk := testutil.RandomEth2PubKey(t)

	expected := &eth2v1.ValidatorRegistration{
		GasLimit:  gasLimit,
		Timestamp: timestamp,
		Pubkey:    pubk,
		FeeRecipient: bellatrix.ExecutionAddress{
			50, 29, 203, 82, 159, 57, 69, 188, 148, 254, 206, 169, 211, 188, 92, 175, 53, 37, 59, 148,
		},
	}

	feeRecipient := "0x321dcb529f3945bc94fecea9d3bc5caf35253b94"

	result, err := registration.NewMessage(pubk, feeRecipient, gasLimit, timestamp)
	require.NoError(t, err)
	require.Equal(t, expected, result)
}

func TestNewMessageBadAddress(t *testing.T) {
	gasLimit := uint64(30000000)

	timestamp, err := time.Parse("Jan 2, 2006", "Jan 1, 2000")
	require.NoError(t, err)

	pubk := testutil.RandomEth2PubKey(t)

	feeRecipient := "0x321dcb529f3945bc94fecea9d3bc5caf35253b9"

	result, err := registration.NewMessage(pubk, feeRecipient, gasLimit, timestamp)

	require.ErrorContains(t, err, "invalid address")
	require.Empty(t, result)
}

func TestGetMessageSigningRoot(t *testing.T) {
	gasLimit := uint64(30000000)

	timestamp, err := time.Parse("Jan 2, 2006", "Jan 1, 2000")
	require.NoError(t, err)

	pubk := testutil.RandomEth2PubKey(t)

	msg := &eth2v1.ValidatorRegistration{
		GasLimit:  gasLimit,
		Timestamp: timestamp,
		Pubkey:    pubk,
		FeeRecipient: bellatrix.ExecutionAddress{
			50, 29, 203, 82, 159, 57, 69, 188, 148, 254, 206, 169, 211, 188, 92, 175, 53, 37, 59, 148,
		},
	}

	forkVersion, err := eth2util.NetworkToForkVersionBytes(eth2util.Goerli.Name)
	require.NoError(t, err)

	res, err := registration.GetMessageSigningRoot(msg, eth2p0.Version(forkVersion))
	require.NoError(t, err)
	require.NotEmpty(t, res)
	require.Len(t, res, 32)
}

func TestVerifySignedRegistration(t *testing.T) {
	// Test data obtained from teku.
	sk, err := hex.DecodeString("345768c0245f1dc702df9e50e811002f61ebb2680b3d5931527ef59f96cbaf9b")
	require.NoError(t, err)

	secret, err := tblsconv.PrivkeyFromBytes(sk)
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	registrationJSON := `
 {
  "message": {
   "fee_recipient": "0x000000000000000000000000000000000000dead",
   "gas_limit": "30000000",
   "timestamp": "1646092800",
   "pubkey": "0x86966350b672bd502bfbdb37a6ea8a7392e8fb7f5ebb5c5e2055f4ee168ebfab0fef63084f28c9f62c3ba71f825e527e"
  },
  "signature": "0xb101da0fc08addcc5d010ee569f6bbbdca049a5cb27efad231565bff2e3af504ec2bb87b11ed22843e9c1094f1dfe51a0b2a5ad1808df18530a2f59f004032dbf6281ecf0fc3df86d032da5b9d32a3d282c05923de491381f8f28c2863a00180"
 }`

	reg := new(eth2v1.SignedValidatorRegistration)
	err = json.Unmarshal([]byte(registrationJSON), reg)
	require.NoError(t, err)

	forkVersion := eth2p0.Version{0x00, 0x00, 0x10, 0x20}
	sigRoot, err := registration.GetMessageSigningRoot(reg.Message, forkVersion)
	require.NoError(t, err)

	require.NoError(t, tbls.Verify(pubkey, sigRoot[:], tbls.Signature(reg.Signature)))
}
