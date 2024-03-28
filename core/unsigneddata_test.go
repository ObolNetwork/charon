// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core_test

import (
	"fmt"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
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

func TestNewVersionedProposal(t *testing.T) {
	type testCase struct {
		error   string
		version eth2spec.DataVersion
		blinded bool
	}

	tests := []testCase{
		{
			error:   "unknown version",
			version: eth2spec.DataVersion(999),
		},
		{
			error:   "no phase0 block",
			version: eth2spec.DataVersionPhase0,
		},
		{
			error:   "no altair block",
			version: eth2spec.DataVersionAltair,
		},
		{
			error:   "no bellatrix block",
			version: eth2spec.DataVersionBellatrix,
		},
		{
			error:   "no capella block",
			version: eth2spec.DataVersionCapella,
		},
		{
			error:   "no deneb block",
			version: eth2spec.DataVersionDeneb,
		},
		{
			error:   "no bellatrix blinded block",
			version: eth2spec.DataVersionBellatrix,
			blinded: true,
		},
		{
			error:   "no capella blinded block",
			version: eth2spec.DataVersionCapella,
			blinded: true,
		},
		{
			error:   "no deneb blinded block",
			version: eth2spec.DataVersionDeneb,
			blinded: true,
		},
	}

	for _, test := range tests {
		t.Run(test.error, func(t *testing.T) {
			_, err := core.NewVersionedProposal(&eth2api.VersionedProposal{
				Version: test.version,
				Blinded: test.blinded,
			})
			require.ErrorContains(t, err, test.error)
		})
	}

	t.Run("happy path", func(t *testing.T) {
		proposal := testutil.RandomBellatrixCoreVersionedProposal()

		p, err := core.NewVersionedProposal(&proposal.VersionedProposal)
		require.NoError(t, err)
		require.Equal(t, proposal, p)
	})
}

func TestVersionedProposal(t *testing.T) {
	type testCase struct {
		name     string
		proposal eth2api.VersionedProposal
		err      string
	}

	tests := []testCase{
		{
			name: "unknown version",
			proposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionUnknown,
			},
			err: "unknown version",
		},
		{
			name: "phase0",
			proposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionPhase0,
				Phase0:  testutil.RandomPhase0BeaconBlock(),
			},
		},
		{
			name: "phase0 blinded error",
			proposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionPhase0,
				Phase0:  testutil.RandomPhase0BeaconBlock(),
				Blinded: true,
			},
			err: "phase0 block cannot be blinded",
		},
		{
			name: "altair",
			proposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionAltair,
				Altair:  testutil.RandomAltairBeaconBlock(),
			},
		},
		{
			name: "altair blinded error",
			proposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionAltair,
				Altair:  testutil.RandomAltairBeaconBlock(),
				Blinded: true,
			},
			err: "altair block cannot be blinded",
		},
		{
			name: "bellatrix",
			proposal: eth2api.VersionedProposal{
				Version:   eth2spec.DataVersionBellatrix,
				Bellatrix: testutil.RandomBellatrixBeaconBlock(),
			},
		},
		{
			name: "bellatrix blinded",
			proposal: eth2api.VersionedProposal{
				Version:          eth2spec.DataVersionBellatrix,
				BellatrixBlinded: testutil.RandomBellatrixBlindedBeaconBlock(),
				Blinded:          true,
			},
		},
		{
			name: "capella",
			proposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionCapella,
				Capella: testutil.RandomCapellaBeaconBlock(),
			},
		},
		{
			name: "capella blinded",
			proposal: eth2api.VersionedProposal{
				Version:        eth2spec.DataVersionCapella,
				CapellaBlinded: testutil.RandomCapellaBlindedBeaconBlock(),
				Blinded:        true,
			},
		},
		{
			name: "deneb",
			proposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionDeneb,
				Deneb:   testutil.RandomDenebVersionedProposal().Deneb,
			},
		},
		{
			name: "deneb blinded",
			proposal: eth2api.VersionedProposal{
				Version:      eth2spec.DataVersionDeneb,
				DenebBlinded: testutil.RandomDenebBlindedBeaconBlock(),
				Blinded:      true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, err := core.NewVersionedProposal(&test.proposal)
			if err != nil {
				require.ErrorContains(t, err, test.err)

				return
			}

			clone, err := p.Clone()
			if test.err != "" {
				require.ErrorContains(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, p, clone)

				js, err := p.MarshalJSON()
				require.NoError(t, err)

				p2 := &core.VersionedProposal{}
				err = p2.UnmarshalJSON(js)
				require.NoError(t, err)
				require.Equal(t, p, *p2)

				// Malformed data
				err = p2.UnmarshalJSON([]byte("malformed"))
				require.ErrorContains(t, err, "unmarshal block")

				if test.proposal.Version != eth2spec.DataVersionUnknown {
					js := fmt.Sprintf(`{"version":%d,"blinded":%v,"block":123}`, test.proposal.Version-1, test.proposal.Blinded)
					err = p2.UnmarshalJSON([]byte(js))
					require.ErrorContains(t, err, "unmarshal "+test.proposal.Version.String())
				}
			}
		})
	}
}
