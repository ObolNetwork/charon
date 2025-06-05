// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package featureset

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAllFeatureStatus(t *testing.T) {
	// Add all features to this test
	features := []Feature{
		MockAlpha,
		EagerDoubleLinear,
		ConsensusParticipate,
		JSONRequests,
		GnosisBlockHotfix,
		Linear,
		SSEReorgDuties,
		AttestationInclusion,
	}

	for _, feature := range features {
		status, ok := state[feature]
		require.True(t, ok)
		require.Positive(t, status)
	}
}
