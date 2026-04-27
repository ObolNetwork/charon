// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/stretchr/testify/require"
)

const classifyExpectedHex = "0xabcd000000000000000000000000000000000000"

func denebProposal(addr bellatrix.ExecutionAddress) *eth2api.VersionedProposal {
	return &eth2api.VersionedProposal{
		Version: eth2spec.DataVersionDeneb,
		Deneb: &eth2deneb.BlockContents{
			Block: &deneb.BeaconBlock{
				Body: &deneb.BeaconBlockBody{
					ExecutionPayload: &deneb.ExecutionPayload{FeeRecipient: addr},
				},
			},
		},
	}
}

func TestClassifyProposal(t *testing.T) {
	matching := bellatrix.ExecutionAddress{0xab, 0xcd}
	mismatching := bellatrix.ExecutionAddress{0xde, 0xad}

	tests := []struct {
		name     string
		proposal *eth2api.VersionedProposal
		want     proposalDecision
	}{
		{
			name:     "matching fee recipient",
			proposal: denebProposal(matching),
			want:     decisionAccept,
		},
		{
			name:     "mismatching fee recipient",
			proposal: denebProposal(mismatching),
			want:     decisionRejectMismatch,
		},
		{
			name: "blinded proposal accepted (recipient is builder's, not validator's)",
			proposal: &eth2api.VersionedProposal{
				Version: eth2spec.DataVersionDeneb,
				Blinded: true,
			},
			want: decisionAccept,
		},
		{
			name:     "phase0 accepted (no execution payload)",
			proposal: &eth2api.VersionedProposal{Version: eth2spec.DataVersionPhase0},
			want:     decisionAccept,
		},
		{
			name:     "altair accepted (no execution payload)",
			proposal: &eth2api.VersionedProposal{Version: eth2spec.DataVersionAltair},
			want:     decisionAccept,
		},
		{
			name:     "nil proposal rejected as malformed",
			proposal: nil,
			want:     decisionRejectMalformed,
		},
		{
			name:     "deneb with nil Deneb rejected as malformed",
			proposal: &eth2api.VersionedProposal{Version: eth2spec.DataVersionDeneb},
			want:     decisionRejectMalformed,
		},
		{
			name: "deneb with nil ExecutionPayload rejected as malformed",
			proposal: &eth2api.VersionedProposal{
				Version: eth2spec.DataVersionDeneb,
				Deneb:   &eth2deneb.BlockContents{Block: &deneb.BeaconBlock{Body: &deneb.BeaconBlockBody{}}},
			},
			want: decisionRejectMalformed,
		},
		{
			name:     "bellatrix with nil Bellatrix rejected as malformed",
			proposal: &eth2api.VersionedProposal{Version: eth2spec.DataVersionBellatrix},
			want:     decisionRejectMalformed,
		},
		{
			name:     "unknown fork rejected as malformed",
			proposal: &eth2api.VersionedProposal{Version: eth2spec.DataVersion(99)},
			want:     decisionRejectMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := classifyProposal(tt.proposal, classifyExpectedHex)
			require.Equal(t, tt.want, got)
		})
	}
}
