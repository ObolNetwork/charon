// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package fetcher

import (
	"context"
	"fmt"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

func TestVerifyFeeRecipient(t *testing.T) {
	type testCase struct {
		name     string
		proposal core.VersionedProposal
		// match is a fee recipient address expected to verify without a warning.
		match string
	}

	const zeroAddr = "0x0000000000000000000000000000000000000000"

	gloasProposal := testutil.RandomGloasCoreVersionedEPBSProposalWithPayload()

	tests := []testCase{
		{
			name: "bellatrix",
			proposal: core.VersionedProposal{VersionedProposal: eth2api.VersionedProposal{
				Version:   eth2spec.DataVersionBellatrix,
				Blinded:   false,
				Bellatrix: testutil.RandomBellatrixBeaconBlock(),
			}},
			match: zeroAddr,
		},
		{
			name: "capella",
			proposal: core.VersionedProposal{VersionedProposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionCapella,
				Blinded: false,
				Capella: testutil.RandomCapellaBeaconBlock(),
			}},
			match: zeroAddr,
		},
		{
			name: "deneb",
			proposal: core.VersionedProposal{VersionedProposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionDeneb,
				Blinded: false,
				Deneb:   testutil.RandomDenebVersionedProposal().Deneb,
			}},
			match: zeroAddr,
		},
		{
			name: "electra",
			proposal: core.VersionedProposal{VersionedProposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionElectra,
				Blinded: false,
				Electra: testutil.RandomElectraVersionedProposal().Electra,
			}},
			match: zeroAddr,
		},
		{
			name: "fulu",
			proposal: core.VersionedProposal{VersionedProposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionFulu,
				Blinded: false,
				Fulu:    testutil.RandomFuluVersionedProposal().Fulu,
			}},
			match: zeroAddr,
		},
		{
			name:     "gloas",
			proposal: gloasProposal,
			match:    fmt.Sprintf("%#x", gloasProposal.EPBS.GloasContents.ExecutionPayloadEnvelope.Payload.FeeRecipient),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buf zaptest.Buffer
			log.InitLogfmtForT(t, &buf)

			verifyFeeRecipient(context.Background(), test.proposal, test.match)
			require.Empty(t, buf.String())

			verifyFeeRecipient(context.Background(), test.proposal, "0xdead")
			require.Contains(t, buf.String(), "Proposal with unexpected fee recipient address")
		})
	}
}
