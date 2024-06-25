// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

var coreTypeFuncs = []func() any{
	func() any { return new(core.VersionedSignedProposal) },
	func() any { return new(core.Attestation) },
	func() any { return new(core.Signature) },
	func() any { return new(core.SignedVoluntaryExit) },

	func() any { return new(core.SignedRandao) },
	func() any { return new(core.BeaconCommitteeSelection) },
	func() any { return new(core.SignedAggregateAndProof) },
	func() any { return new(core.SignedSyncMessage) },
	func() any { return new(core.SyncContributionAndProof) },
	func() any { return new(core.SignedSyncContributionAndProof) },
	func() any { return new(core.SyncCommitteeSelection) },
	func() any { return new(core.AttestationData) },
	func() any { return new(core.AggregatedAttestation) },
	func() any { return new(core.VersionedProposal) },
	func() any { return new(core.SyncContribution) },
}

//go:generate go test . -run=TestJSONSerialisation -update

func TestJSONSerialisation(t *testing.T) {
	for _, typFunc := range coreTypeFuncs {
		any1, any2 := typFunc(), typFunc()

		name := fmt.Sprintf("%T", any1)
		name = strings.TrimPrefix(name, "*core.")
		name += ".json"

		t.Run(name, func(t *testing.T) {
			testutil.NewEth2Fuzzer(t, 1).Fuzz(any1)

			b, err := json.MarshalIndent(any1, "", "  ")
			testutil.RequireNoError(t, err)
			testutil.RequireGoldenBytes(t, b)

			err = json.Unmarshal(b, any2)
			testutil.RequireNoError(t, err)
			require.Equal(t, any1, any2)
		})
	}
}
