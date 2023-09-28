// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
			data: core.NewAttestation(testutil.RandomAttestation()),
		},
		{
			name: "verify beacon block",
			data: testutil.RandomDenebCoreVersionedSignedBeaconBlock(),
		},
		{
			name: "verify blinded beacon block bellatrix",
			data: testutil.RandomBellatrixVersionedSignedBlindedBeaconBlock(),
		},
		{
			name: "verify blinded beacon block capella",
			data: testutil.RandomCapellaVersionedSignedBlindedBeaconBlock(),
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

			roots, err := test.data.MessageRoots()
			require.NoError(t, err)

			domains := test.data.DomainNames()

			privkey, err := tbls.GenerateSecretKey()
			require.NoError(t, err)
			pubkey, err := tbls.SecretToPublicKey(privkey)
			require.NoError(t, err)

			var sigs []core.Signature
			for i := 0; i < len(roots); i++ {
				sigData, err := signing.GetDataRoot(context.Background(), bmock, domains[i], epoch, roots[i])
				require.NoError(t, err)

				sig := signWithKey(t, sigData[:], privkey)
				sigs = append(sigs, sig)
			}

			s, err := test.data.SetSignatures(sigs)
			require.NoError(t, err)

			eth2Signed, ok := s.(core.Eth2SignedData)
			require.True(t, ok)

			require.NoError(t, core.VerifyEth2SignedData(context.Background(), bmock, eth2Signed, pubkey))
		})
	}
}

func signWithKey(t *testing.T, data []byte, secret tbls.PrivateKey) core.Signature {
	t.Helper()

	sig, err := tbls.Sign(secret, data)
	require.NoError(t, err)

	return tblsconv.SigToCore(sig)
}
