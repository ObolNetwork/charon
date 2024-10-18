// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package signing_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/registration"
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
			"fee_recipient": "0x000000000000000000000000000000000000dEaD",
			"gas_limit": "30000000",
			"timestamp": "1646092800",
			"pubkey": "0x86966350b672bd502bfbdb37a6ea8a7392e8fb7f5ebb5c5e2055f4ee168ebfab0fef63084f28c9f62c3ba71f825e527e"
		  },
		  "signature": "0xad393c5b42b382cf93cd14f302b0175b4f9ccb000c201d42c3a6389971b8d910a81333d55ad2944b836a9bb35ba968ab06635dcd706380516ad0c653f48b1c6d52b8771c78d708e943b3ea8da59392fbf909decde262adc944fe3e57120d9bb4"
		}`

	reg := new(eth2v1.SignedValidatorRegistration)
	err = json.Unmarshal([]byte(registrationJSON), reg)
	require.NoError(t, err)

	sigRoot, err := reg.Message.HashTreeRoot()
	require.NoError(t, err)

	fork, err := eth2util.NetworkToForkVersionBytes("holesky")
	require.NoError(t, err)

	sigData, err := registration.GetMessageSigningRoot(reg.Message, eth2p0.Version(fork))
	require.NoError(t, err)

	sig, err := tbls.Sign(secretShare, sigData[:])
	require.NoError(t, err)

	sigEth2 := eth2p0.BLSSignature(sig)
	require.Equal(t,
		hex.EncodeToString(reg.Signature[:]),
		hex.EncodeToString(sigEth2[:]),
	)

	pubkey, err := tbls.SecretToPublicKey(secretShare)
	require.NoError(t, err)

	err = signing.Verify(context.Background(), bmock, signing.DomainApplicationBuilder, 0, sigRoot, eth2p0.BLSSignature(sig), pubkey)
	require.NoError(t, err)
}

func TestConstantApplicationBuilder(t *testing.T) {
	v0 := eth2p0.Version{0x01, 0x01, 0x70, 0x00}
	v1 := eth2p0.Version{0x02, 0x01, 0x70, 0x00}
	v2 := eth2p0.Version{0x03, 0x01, 0x70, 0x00}
	v3 := eth2p0.Version{0x04, 0x01, 0x70, 0x00}

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
		eth2Cl.ForkScheduleFunc = func(ctx context.Context, opts *eth2api.ForkScheduleOpts) ([]*eth2p0.Fork, error) {
			return forkSchedule[0:i], nil
		}

		domain, err := signing.GetDomain(context.Background(), eth2Cl, signing.DomainApplicationBuilder, 0) // Always use epoch 0 for DomainApplicationBuilder.
		require.NoError(t, err)

		return domain
	}

	// Assert genesis domain is used for any fork schedule.
	expect := eth2p0.Domain{
		0x0, 0x0, 0x0, 0x1, 0x5b, 0x83, 0xa2, 0x37,
		0x59, 0xc5, 0x60, 0xb2, 0xd0, 0xc6, 0x45, 0x76,
		0xe1, 0xdc, 0xfc, 0x34, 0xea, 0x94, 0xc4, 0x98,
		0x8f, 0x3e, 0xd, 0x9f, 0x77, 0xf0, 0x53, 0x87,
	}

	for i := range len(forkSchedule) {
		domain := getDomain(t, i)
		require.Equal(t, expect, domain, "domain for fork schedule %d", i)
	}
}
