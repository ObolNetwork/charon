// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package fetcher

import (
	"context"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/testutil"
)

func TestVerifyFeeRecipient(t *testing.T) {
	type testCase struct {
		name     string
		proposal eth2api.VersionedProposal
	}

	tests := []testCase{
		{
			name: "bellatrix",
			proposal: eth2api.VersionedProposal{
				Version:   eth2spec.DataVersionBellatrix,
				Blinded:   false,
				Bellatrix: testutil.RandomBellatrixBeaconBlock(),
			},
		},
		{
			name: "capella",
			proposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionCapella,
				Blinded: false,
				Capella: testutil.RandomCapellaBeaconBlock(),
			},
		},
		{
			name: "deneb",
			proposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionDeneb,
				Blinded: false,
				Deneb:   testutil.RandomDenebVersionedProposal().Deneb,
			},
		},
		{
			name: "electra",
			proposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionElectra,
				Blinded: false,
				Electra: testutil.RandomElectraVersionedProposal().Electra,
			},
		},
		{
			name: "fulu",
			proposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionFulu,
				Blinded: false,
				Fulu:    testutil.RandomFuluVersionedProposal().Fulu,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buf zaptest.Buffer
			log.InitLogfmtForT(t, &buf)

			verifyFeeRecipient(context.Background(), &test.proposal, "0x0000000000000000000000000000000000000000")
			require.Empty(t, buf.String())

			verifyFeeRecipient(context.Background(), &test.proposal, "0xdead")
			require.Contains(t, buf.String(), "Proposal with unexpected fee recipient address")
		})
	}
}
