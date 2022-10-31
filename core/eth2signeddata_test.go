// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package core_test

import (
	"context"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
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
			data: testutil.RandomCoreVersionSignedBeaconBlock(t),
		},
		{
			name: "verify blinded beacon block",
			data: testutil.RandomCoreVersionSignedBlindedBeaconBlock(t),
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

			sigData, err := signing.GetDataRoot(context.Background(), bmock, test.data.DomainName(), epoch, root)
			require.NoError(t, err)

			sig, pubkey := sign(t, sigData[:])

			s, err := test.data.SetSignature(sig)
			require.NoError(t, err)

			eth2Signed, ok := s.(core.Eth2SignedData)
			require.True(t, ok)

			require.NoError(t, core.VerifyEth2SignedData(context.Background(), bmock, eth2Signed, pubkey))
		})
	}
}

func sign(t *testing.T, data []byte) (core.Signature, *bls_sig.PublicKey) {
	t.Helper()

	pk, secret, err := tbls.Keygen()
	require.NoError(t, err)

	sig, err := tbls.Sign(secret, data)
	require.NoError(t, err)

	return tblsconv.SigToCore(sig), pk
}
