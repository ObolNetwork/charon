// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dutydb

import (
	"testing"

	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

// TestNoPayloadAttestationData asserts that only the zero value marks an agreed no-block slot,
// independent of which fork's data field is populated.
func TestNoPayloadAttestationData(t *testing.T) {
	require.True(t, noPayloadAttestationData(core.VersionedPayloadAttestationData{}))

	data, err := core.NewVersionedPayloadAttestationData(testutil.RandomVersionedPayloadAttestationData())
	require.NoError(t, err)
	require.False(t, noPayloadAttestationData(data))

	// A version without data is malformed, not the no-block marker.
	malformed := core.VersionedPayloadAttestationData{
		Version: eth2spec.DataVersionGloas,
	}
	require.False(t, noPayloadAttestationData(malformed))
}
