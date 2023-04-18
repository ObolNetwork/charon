// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package signing_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestVerifyRegistrationReference(t *testing.T) {
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Test data obtained from teku.

	secretShareBytes, err := hex.DecodeString("345768c0245f1dc702df9e50e811002f61ebb2680b3d5931527ef59f96cbaf9b")
	require.NoError(t, err)

	secretShare, err := tblsconv.PrivkeyFromBytes(secretShareBytes)
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

	registration := new(eth2v1.SignedValidatorRegistration)
	err = json.Unmarshal([]byte(registrationJSON), registration)
	require.NoError(t, err)

	sigRoot, err := registration.Message.HashTreeRoot()
	require.NoError(t, err)

	sigData, err := signing.GetDataRoot(context.Background(), bmock, signing.DomainApplicationBuilder, 0, sigRoot)
	require.NoError(t, err)

	sig, err := tbls.Sign(secretShare, sigData[:])
	require.NoError(t, err)

	sigEth2 := eth2p0.BLSSignature(sig)
	require.Equal(t,
		fmt.Sprintf("%x", registration.Signature),
		fmt.Sprintf("%x", sigEth2),
	)

	pubkey, err := tbls.SecretToPublicKey(secretShare)
	require.NoError(t, err)

	err = signing.Verify(context.Background(), bmock, signing.DomainApplicationBuilder, 0, sigRoot, eth2p0.BLSSignature(sig), pubkey)
	require.NoError(t, err)
}
