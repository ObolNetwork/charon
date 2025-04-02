// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core_test

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -run=TestSSZSerialisation -update

func TestSSZSerialisation(t *testing.T) {
	for _, typFunc := range coreTypeFuncs {
		any1, any2 := typFunc(), typFunc()

		name := fmt.Sprintf("%T", any1)
		name = strings.TrimPrefix(name, "*core.")
		name += ".ssz"

		if _, ok := any1.(ssz.Marshaler); !ok {
			t.Logf("Skipping non SSZ type: %v", name)
			continue
		}

		t.Run(name, func(t *testing.T) {
			testutil.NewEth2Fuzzer(t, 1).Fuzz(any1)

			b, err := ssz.MarshalSSZ(any1.(ssz.Marshaler))
			testutil.RequireNoError(t, err)
			testutil.RequireGoldenBytes(t, b)

			err = any2.(ssz.Unmarshaler).UnmarshalSSZ(b)
			testutil.RequireNoError(t, err)
			require.Equal(t, any1, any2)
		})
	}
}

// TestSSZ tests SSZ marshalling and unmarshalling.
func TestSSZ(t *testing.T) {
	tests := []struct {
		zero func() any
	}{
		{zero: func() any { return new(core.VersionedSignedProposal) }},
		{zero: func() any { return new(core.VersionedAttestation) }},
		{zero: func() any { return new(core.VersionedSignedAggregateAndProof) }},
		{zero: func() any { return new(core.SignedSyncMessage) }},
		{zero: func() any { return new(core.SyncContributionAndProof) }},
		{zero: func() any { return new(core.SignedSyncContributionAndProof) }},
		{zero: func() any { return new(core.VersionedAggregatedAttestation) }},
		{zero: func() any { return new(core.VersionedProposal) }},
		{zero: func() any { return new(core.SyncContribution) }},
	}

	f := testutil.NewEth2Fuzzer(t, 0)

	for _, test := range tests {
		t.Run(fmt.Sprintf("%T", test.zero()), func(t *testing.T) {
			val1, val2 := test.zero(), test.zero()

			f.Fuzz(val1)

			marshaller, ok := val1.(ssz.Marshaler)
			require.True(t, ok)

			b, err := marshaller.MarshalSSZ()
			testutil.RequireNoError(t, err)

			unmarshaller, ok := val2.(ssz.Unmarshaler)
			require.True(t, ok)

			err = unmarshaller.UnmarshalSSZ(b)
			testutil.RequireNoError(t, err)

			require.Equal(t, val1, val2)
		})
	}
}

func TestMarshalUnsignedProto(t *testing.T) {
	tests := []struct {
		unsignedPtr func() any // Need any pointer to avoid wrapping in interface which doesnt' support fuzzing.
		dutyType    core.DutyType
	}{
		{
			dutyType:    core.DutyAttester,
			unsignedPtr: func() any { return new(core.AttestationData) },
		},
		{
			dutyType:    core.DutyAggregator,
			unsignedPtr: func() any { return new(core.VersionedAggregatedAttestation) },
		},
		{
			dutyType:    core.DutyProposer,
			unsignedPtr: func() any { return new(core.VersionedProposal) },
		},
		{
			dutyType:    core.DutySyncContribution,
			unsignedPtr: func() any { return new(core.SyncContribution) },
		},
	}

	jsonSizes := make(map[string]int)
	sszSizes := make(map[string]int)

	seed := time.Now().Unix()

	for _, disableSSZ := range []bool{true, false} {
		for i, test := range tests {
			f := testutil.NewEth2Fuzzer(t, seed+int64(i)) // Use the same seed for ssz vs json for each type.

			t.Run(fmt.Sprintf("%T_%v", test.unsignedPtr(), disableSSZ), func(t *testing.T) {
				if disableSSZ {
					core.DisableSSZMarshallingForT(t)
				}

				unsignedPtr := test.unsignedPtr()
				f.Fuzz(unsignedPtr)

				// Dereference the pointer to get the unsigned data.
				unsigned := reflect.ValueOf(unsignedPtr).Elem().Interface().(core.UnsignedData)

				set := core.UnsignedDataSet{
					testutil.RandomCorePubKey(t): unsigned,
				}

				pb, err := core.UnsignedDataSetToProto(set)
				require.NoError(t, err)

				set2, err := core.UnsignedDataSetFromProto(test.dutyType, pb)
				require.NoError(t, err)

				require.Equal(t, set, set2)

				b, err := proto.Marshal(pb)
				require.NoError(t, err)
				if disableSSZ {
					jsonSizes[fmt.Sprintf("%T", unsignedPtr)] = len(b)
				} else {
					sszSizes[fmt.Sprintf("%T", unsignedPtr)] = len(b)
				}
			})
		}
	}

	for _, test := range tests {
		typ := fmt.Sprintf("%T", test.unsignedPtr())
		jsonSize := jsonSizes[typ]
		sszSize := sszSizes[typ]
		t.Logf("%s: ssz (%d) vs json (%d) == %.0f%%", typ, sszSize, jsonSize, 100*float64(sszSize)/float64(jsonSize))
	}
}

func TestMarshalParSignedProto(t *testing.T) {
	tests := []struct {
		signedPtr func() any // Need any pointer to avoid wrapping in interface which doesnt' support fuzzing.
		dutyType  core.DutyType
	}{
		{
			dutyType:  core.DutyAttester,
			signedPtr: func() any { return new(core.VersionedAttestation) },
		},
		{
			dutyType:  core.DutyAggregator,
			signedPtr: func() any { return new(core.VersionedSignedAggregateAndProof) },
		},
		{
			dutyType:  core.DutyProposer,
			signedPtr: func() any { return new(core.VersionedSignedProposal) },
		},
		{
			dutyType:  core.DutySyncContribution,
			signedPtr: func() any { return new(core.SignedSyncContributionAndProof) },
		},
	}

	jsonSizes := make(map[string]int)
	sszSizes := make(map[string]int)

	seed := time.Now().Unix()

	for _, disabledSSZ := range []bool{true, false} {
		for i, test := range tests {
			f := testutil.NewEth2Fuzzer(t, seed+int64(i)) // Use the same seed for ssz vs json for each type.

			t.Run(fmt.Sprintf("%T_%v", test.signedPtr(), disabledSSZ), func(t *testing.T) {
				if disabledSSZ {
					core.DisableSSZMarshallingForT(t)
				}

				signedPtr := test.signedPtr()
				f.Fuzz(signedPtr)

				// Dereference the pointer to get the signed data.
				signed := reflect.ValueOf(signedPtr).Elem().Interface().(core.SignedData)

				set := core.ParSignedDataSet{
					testutil.RandomCorePubKey(t): core.ParSignedData{
						SignedData: signed,
						ShareIdx:   rand.Intn(10),
					},
				}

				pb, err := core.ParSignedDataSetToProto(set)
				require.NoError(t, err)

				set2, err := core.ParSignedDataSetFromProto(test.dutyType, pb)
				require.NoError(t, err)

				require.Equal(t, set, set2)

				b, err := proto.Marshal(pb)
				require.NoError(t, err)
				if disabledSSZ {
					jsonSizes[fmt.Sprintf("%T", signedPtr)] = len(b)
				} else {
					sszSizes[fmt.Sprintf("%T", signedPtr)] = len(b)
				}
			})
		}
	}

	for _, test := range tests {
		typ := fmt.Sprintf("%T", test.signedPtr())
		jsonSize := jsonSizes[typ]
		sszSize := sszSizes[typ]
		t.Logf("%s: ssz (%d) vs json (%d) == %.2f%%", typ, sszSize, jsonSize, 100*float64(sszSize)/float64(jsonSize))
	}
}

func TestV3SignedProposalSSZSerialisation(t *testing.T) {
	type testCase struct {
		name     string
		proposal eth2api.VersionedSignedProposal
	}

	tests := []testCase{
		{
			name: "phase0",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionPhase0,
				Phase0: &eth2p0.SignedBeaconBlock{
					Message:   testutil.RandomPhase0BeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
			},
		},
		{
			name: "altair",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionAltair,
				Altair: &altair.SignedBeaconBlock{
					Message:   testutil.RandomAltairBeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
			},
		},
		{
			name: "bellatrix",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBeaconBlock{
					Message:   testutil.RandomBellatrixBeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
			},
		},
		{
			name: "bellatrix blinded",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionBellatrix,
				BellatrixBlinded: &eth2bellatrix.SignedBlindedBeaconBlock{
					Message:   testutil.RandomBellatrixBlindedBeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
				Blinded: true,
			},
		},
		{
			name: "capella",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionCapella,
				Capella: &capella.SignedBeaconBlock{
					Message:   testutil.RandomCapellaBeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
			},
		},
		{
			name: "capella blinded",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionCapella,
				CapellaBlinded: &eth2capella.SignedBlindedBeaconBlock{
					Message:   testutil.RandomCapellaBlindedBeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
				Blinded: true,
			},
		},
		{
			name: "deneb",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionDeneb,
				Deneb:   testutil.RandomDenebVersionedSignedProposal().Deneb,
			},
		},
		{
			name: "deneb blinded",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionDeneb,
				DenebBlinded: &eth2deneb.SignedBlindedBeaconBlock{
					Message:   testutil.RandomDenebBlindedBeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
				Blinded: true,
			},
		},
		{
			name: "electra",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionElectra,
				Electra: testutil.RandomElectraVersionedSignedProposal().Electra,
			},
		},
		{
			name: "electra blinded",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionElectra,
				ElectraBlinded: &eth2electra.SignedBlindedBeaconBlock{
					Message:   testutil.RandomElectraBlindedBeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
				Blinded: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, err := core.NewVersionedSignedProposal(&test.proposal)
			require.NoError(t, err)

			b, err := ssz.MarshalSSZ(p)
			require.NoError(t, err)

			p2 := new(core.VersionedSignedProposal)
			p2.Blinded = p.Blinded
			err = p2.UnmarshalSSZ(b)
			require.NoError(t, err)
			require.Equal(t, p, *p2)
		})
	}
}

func TestV3ProposalSSZSerialisation(t *testing.T) {
	type testCase struct {
		name     string
		proposal eth2api.VersionedProposal
	}

	tests := []testCase{
		{
			name: "phase0",
			proposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionPhase0,
				Phase0:  testutil.RandomPhase0BeaconBlock(),
			},
		},
		{
			name: "altair",
			proposal: eth2api.VersionedProposal{
				Version: eth2spec.DataVersionAltair,
				Altair:  testutil.RandomAltairBeaconBlock(),
			},
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
			require.NoError(t, err)

			b, err := ssz.MarshalSSZ(p)
			require.NoError(t, err)

			p2 := new(core.VersionedProposal)
			p2.Blinded = p.Blinded
			err = p2.UnmarshalSSZ(b)
			require.NoError(t, err)
			require.Equal(t, p, *p2)
		})
	}
}
