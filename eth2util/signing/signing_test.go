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

func TestConstantApplicationBuilder(t *testing.T) {
	v0 := eth2p0.Version{0x00, 0x00, 0x10, 0x20}
	v1 := eth2p0.Version{0x01, 0x00, 0x10, 0x20}
	v2 := eth2p0.Version{0x02, 0x00, 0x10, 0x20}
	v3 := eth2p0.Version{0x03, 0x00, 0x10, 0x20}

	forkSchedule := []*eth2p0.Fork{
		{PreviousVersion: v0, CurrentVersion: v0, Epoch: 0},
		{PreviousVersion: v0, CurrentVersion: v1, Epoch: 1},
		{PreviousVersion: v1, CurrentVersion: v2, Epoch: 2},
		{PreviousVersion: v2, CurrentVersion: v3, Epoch: 3},
	}

	getDomain := func(t *testing.T, i int) eth2p0.Domain {
		t.Helper()
		eth2Cl, err := beaconmock.New()
		require.NoError(t, err)
		eth2Cl.ForkScheduleFunc = func(ctx context.Context) ([]*eth2p0.Fork, error) {
			return forkSchedule[0:i], nil
		}

		domain, err := signing.GetDomain(context.Background(), eth2Cl, signing.DomainApplicationBuilder, 0) // Always use epoch 0 for DomainApplicationBuilder.
		require.NoError(t, err)

		return domain
	}

	// Assert genesis domain is used for any fork schedule.
	expect := eth2p0.Domain{
		0x00, 0x00, 0x00, 0x01, 0xe4, 0xbe, 0x93, 0x93,
		0xb0, 0x74, 0xca, 0x1f, 0x3e, 0x4a, 0xab, 0xd5,
		0x85, 0xca, 0x4b, 0xea, 0x10, 0x11, 0x70, 0xcc,
		0xfa, 0xf7, 0x1b, 0x89, 0xce, 0x5c, 0x5c, 0x38,
	}

	for i := 0; i < len(forkSchedule); i++ {
		domain := getDomain(t, i)
		require.Equal(t, expect, domain, "domain for fork schedule %d", i)
	}
}
