// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core_test

import (
	"context"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestVerifyEth2SignedData(t *testing.T) {
	tests := []struct {
		name string
		data core.Eth2SignedData
	}{
		{
			name: "verify attestation",
			data: testutil.RandomDenebCoreVersionedAttestation(),
		},
		{
			name: "verify beacon block",
			data: testutil.RandomBellatrixCoreVersionedSignedProposal(),
		},
		{
			name: "verify randao",
			data: testutil.RandomCoreSignedRandao(),
		},
		{
			name: "verify voluntary exit",
			data: core.NewSignedVoluntaryExit(testutil.RandomExit()),
		},
		{
			name: "verify registration",
			data: testutil.RandomCoreVersionedSignedValidatorRegistration(t),
		},
		{
			name: "verify beacon committee selection",
			data: testutil.RandomCoreBeaconCommitteeSelection(),
		},
		{
			name: "verify attestation aggregate and proof",
			data: core.SignedAggregateAndProof{
				SignedAggregateAndProof: eth2p0.SignedAggregateAndProof{
					Message: testutil.RandomAggregateAndProof(),
				},
			},
		},
		{
			name: "verify sync committee message",
			data: core.NewSignedSyncMessage(testutil.RandomSyncCommitteeMessage()),
		},
		{
			name: "verify sync committee contribution and proof",
			data: core.NewSignedSyncContributionAndProof(testutil.RandomSignedSyncContributionAndProof()),
		},
		{
			name: "verify sync committee selection",
			data: core.NewSyncCommitteeSelection(testutil.RandomSyncCommitteeSelection()),
		},
		{
			name: "verify sync committee selection",
			data: testutil.RandomCoreSyncCommitteeSelection(),
		},
		{
			name: "verify sync contribution and proof",
			data: testutil.RandomCoreSignedSyncContributionAndProof(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bmock, err := beaconmock.New()
			require.NoError(t, err)

			epoch, err := test.data.Epoch(context.Background(), bmock)
			require.NoError(t, err)

			root, err := test.data.MessageRoot()
			require.NoError(t, err)

			// Generate private key to sign data
			secret, err := tbls.GenerateSecretKey()
			require.NoError(t, err)

			pubkey, err := tbls.SecretToPublicKey(secret)
			require.NoError(t, err)

			sigData, err := signing.GetDataRoot(context.Background(), bmock, test.data.DomainName(), epoch, root)
			require.NoError(t, err)

			sig := sign(t, secret, sigData[:])

			s, err := test.data.SetSignature(sig)
			require.NoError(t, err)

			eth2Signed, ok := s.(core.Eth2SignedData)
			require.True(t, ok)

			require.NoError(t, core.VerifyEth2SignedData(context.Background(), bmock, eth2Signed, pubkey))
		})
	}
}

func sign(t *testing.T, secret tbls.PrivateKey, data []byte) core.Signature {
	t.Helper()

	sig, err := tbls.Sign(secret, data)
	require.NoError(t, err)

	return tblsconv.SigToCore(sig)
}
