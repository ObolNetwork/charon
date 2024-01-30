// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

func TestUnsignedDataClone(t *testing.T) {
	tests := []struct {
		name string
		data core.UnsignedData
	}{
		{
			name: "attestation data",
			data: testutil.RandomCoreAttestationData(t),
		},
		{
			name: "versioned beacon block bellatrix",
			data: testutil.RandomBellatrixCoreVersionedProposal(),
		},
		{
			name: "versioned blinded beacon block bellatrix",
			data: testutil.RandomBellatrixVersionedBlindedProposal(),
		},
		{
			name: "versioned beacon block capella",
			data: testutil.RandomCapellaCoreVersionedProposal(),
		},
		{
			name: "versioned blinded beacon block capella",
			data: testutil.RandomCapellaVersionedBlindedProposal(),
		},
		{
			name: "aggregated attestation",
			data: core.NewAggregatedAttestation(testutil.RandomAttestation()),
		},
		{
			name: "sync contribution",
			data: testutil.RandomCoreSyncContribution(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clone, err := test.data.Clone()
			require.NoError(t, err)
			require.Equal(t, test.data, clone)
		})
	}
}
