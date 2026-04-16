// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	bmock, err := beaconmock.New(t.Context())
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
		  "signature": "0x838c82166e22fc27998fee74319daf42545f9fd32ae0e5d69319c888739a2c817f82aab48f04f165e32304d2ab8d317c1318d6d907dbe6372417fcfc4e3f0b550c357d5087abda4b80c021a64d2463e43efb017eeb1cef0dd92e38770b9628a1"
		}`

	reg := new(eth2v1.SignedValidatorRegistration)
	err = json.Unmarshal([]byte(registrationJSON), reg)
	require.NoError(t, err)

	sigRoot, err := reg.Message.HashTreeRoot()
	require.NoError(t, err)

	fork, err := eth2util.NetworkToForkVersionBytes("hoodi")
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

		eth2Cl, err := beaconmock.New(t.Context())
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
		0x0, 0x0, 0x0, 0x1, 0x71, 0x91, 0x3, 0x51,
		0x1e, 0xfa, 0x4f, 0x13, 0x62, 0xff, 0x2a, 0x50,
		0x99, 0x6c, 0xcc, 0xf3, 0x29, 0xcc, 0x84, 0xcb,
		0x41, 0xc, 0x5e, 0x5c, 0x7d, 0x35, 0x1d, 0x3,
	}

	for i := range len(forkSchedule) {
		domain := getDomain(t, i)
		require.Equal(t, expect, domain, "domain for fork schedule %d", i)
	}
}
