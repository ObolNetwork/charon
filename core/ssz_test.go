// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core_test

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	bitfield "github.com/OffchainLabs/go-bitfield"
	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
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
		unsignedPtr func() any // Need any pointer to avoid wrapping in interface which doesn't support fuzzing.
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
		signedPtr func() any // Need any pointer to avoid wrapping in interface which doesn't support fuzzing.
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
		{
			name: "fulu",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionFulu,
				Fulu:    testutil.RandomFuluVersionedSignedProposal().Fulu,
			},
		},
		{
			name: "fulu blinded",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionFulu,
				FuluBlinded: &eth2electra.SignedBlindedBeaconBlock{
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

func TestValIdxVersionedAttestation(t *testing.T) {
	f := testutil.NewEth2Fuzzer(t, 0)

	val1, val2 := new(core.VersionedAttestation), new(core.VersionedAttestation)

	f.Fuzz(val1)

	// Assert that we can successfully unmarshal attestation without ValidatorIndex.
	val1.ValidatorIndex = nil

	b, err := val1.MarshalSSZ()
	testutil.RequireNoError(t, err)

	err = val2.UnmarshalSSZ(b)
	testutil.RequireNoError(t, err)

	require.Equal(t, val1, val2)
}

func TestAttestationDataSSZ(t *testing.T) {
	// Pre-declare fixed-size arrays used across multiple test cases.
	var rootAB, rootCD, rootEF eth2p0.Root
	for i := range rootAB {
		rootAB[i] = 0xab
		rootCD[i] = 0xcd
		rootEF[i] = 0xef
	}

	var pubKey01 eth2p0.BLSPubKey
	for i := range pubKey01 {
		pubKey01[i] = 0x01
	}

	tests := []struct {
		name     string
		value    core.AttestationData
		expected string
	}{
		{
			name: "zeros",
			// All fields zero. Source/Target must be non-nil for valid SSZ.
			value: core.AttestationData{
				Data: eth2p0.AttestationData{
					Source: new(eth2p0.Checkpoint),
					Target: new(eth2p0.Checkpoint),
				},
				Duty: eth2v1.AttesterDuty{},
			},
			// offset0=8 (08000000), offset1=136 (88000000), 224 zero bytes.
			expected: "0x0800000088000000" +
				"0000000000000000" + // Slot (8 bytes)
				"0000000000000000" + // Index (8 bytes)
				"0000000000000000000000000000000000000000000000000000000000000000" + // BeaconBlockRoot (32 bytes)
				"0000000000000000" + // Source.Epoch
				"0000000000000000000000000000000000000000000000000000000000000000" + // Source.Root (32 bytes)
				"0000000000000000" + // Target.Epoch
				"0000000000000000000000000000000000000000000000000000000000000000" + // Target.Root (32 bytes)
				"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" + // PubKey (48 bytes)
				"0000000000000000" + // Duty.Slot
				"0000000000000000" + // Duty.ValidatorIndex
				"0000000000000000" + // Duty.CommitteeIndex
				"0000000000000000" + // Duty.CommitteeLength
				"0000000000000000" + // Duty.CommitteesAtSlot
				"0000000000000000", // Duty.ValidatorCommitteeIndex
		},
		{
			name: "specific_values",
			value: core.AttestationData{
				Data: eth2p0.AttestationData{
					Slot:   1,
					Index:  2,
					Source: &eth2p0.Checkpoint{Epoch: 0},
					Target: &eth2p0.Checkpoint{Epoch: 0},
				},
				Duty: eth2v1.AttesterDuty{
					CommitteeIndex:  3,
					CommitteeLength: 4,
				},
			},
			// offset0=8, offset1=136, AttestationData with Slot=1/Index=2, duty with CommitteeIndex=3/Length=4.
			expected: "0x0800000088000000" +
				"0100000000000000" + // Slot = 1
				"0200000000000000" + // Index = 2
				"0000000000000000000000000000000000000000000000000000000000000000" + // BeaconBlockRoot (32 bytes)
				"0000000000000000" + // Source.Epoch = 0
				"0000000000000000000000000000000000000000000000000000000000000000" + // Source.Root (32 bytes)
				"0000000000000000" + // Target.Epoch = 0
				"0000000000000000000000000000000000000000000000000000000000000000" + // Target.Root (32 bytes)
				"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" + // PubKey (48 bytes)
				"0000000000000000" + // Duty.Slot = 0
				"0000000000000000" + // Duty.ValidatorIndex = 0
				"0300000000000000" + // Duty.CommitteeIndex = 3
				"0400000000000000" + // Duty.CommitteeLength = 4
				"0000000000000000" + // Duty.CommitteesAtSlot = 0
				"0000000000000000", // Duty.ValidatorCommitteeIndex = 0
		},
		{
			name: "all_data_fields",
			// Exercises every AttestationData field with non-zero values; Duty is zero.
			value: core.AttestationData{
				Data: eth2p0.AttestationData{
					Slot:            12345,
					Index:           7,
					BeaconBlockRoot: rootAB,
					Source:          &eth2p0.Checkpoint{Epoch: 100, Root: rootCD},
					Target:          &eth2p0.Checkpoint{Epoch: 101, Root: rootEF},
				},
				Duty: eth2v1.AttesterDuty{},
			},
			// Slot=12345=0x3039, Index=7, roots filled, epochs 100/101.
			expected: "0x0800000088000000" +
				"3930000000000000" + // Slot = 12345 (0x3039 LE)
				"0700000000000000" + // Index = 7
				strings.Repeat("ab", 32) + // BeaconBlockRoot
				"6400000000000000" + // Source.Epoch = 100 (0x64)
				strings.Repeat("cd", 32) + // Source.Root
				"6500000000000000" + // Target.Epoch = 101 (0x65)
				strings.Repeat("ef", 32) + // Target.Root
				strings.Repeat("00", 48) + // PubKey (zero)
				"0000000000000000" + // Duty.Slot = 0
				"0000000000000000" + // Duty.ValidatorIndex = 0
				"0000000000000000" + // Duty.CommitteeIndex = 0
				"0000000000000000" + // Duty.CommitteeLength = 0
				"0000000000000000" + // Duty.CommitteesAtSlot = 0
				"0000000000000000", // Duty.ValidatorCommitteeIndex = 0
		},
		{
			name: "all_duty_fields",
			// Exercises every AttesterDuty field; AttestationData fields are minimal.
			value: core.AttestationData{
				Data: eth2p0.AttestationData{
					Source: new(eth2p0.Checkpoint),
					Target: new(eth2p0.Checkpoint),
				},
				Duty: eth2v1.AttesterDuty{
					PubKey:                  pubKey01,
					Slot:                    9999,
					ValidatorIndex:          42,
					CommitteeIndex:          3,
					CommitteeLength:         128,
					CommitteesAtSlot:        64,
					ValidatorCommitteeIndex: 7,
				},
			},
			// Slot=9999=0x270F, ValidatorIndex=42=0x2A, CommitteeIndex=3, Length=128=0x80,
			// CommitteesAtSlot=64=0x40, ValidatorCommitteeIndex=7.
			expected: "0x0800000088000000" +
				strings.Repeat("00", 8) + // Data.Slot = 0
				strings.Repeat("00", 8) + // Data.Index = 0
				strings.Repeat("00", 32) + // BeaconBlockRoot (zero)
				strings.Repeat("00", 8) + // Source.Epoch = 0
				strings.Repeat("00", 32) + // Source.Root (zero)
				strings.Repeat("00", 8) + // Target.Epoch = 0
				strings.Repeat("00", 32) + // Target.Root (zero)
				strings.Repeat("01", 48) + // PubKey (all 0x01)
				"0f27000000000000" + // Duty.Slot = 9999 (0x270F LE)
				"2a00000000000000" + // Duty.ValidatorIndex = 42
				"0300000000000000" + // Duty.CommitteeIndex = 3
				"8000000000000000" + // Duty.CommitteeLength = 128
				"4000000000000000" + // Duty.CommitteesAtSlot = 64
				"0700000000000000", // Duty.ValidatorCommitteeIndex = 7
		},
		{
			name: "full",
			// All fields populated with distinct non-zero values.
			value: core.AttestationData{
				Data: eth2p0.AttestationData{
					Slot:            4294967295, // max uint32
					Index:           255,
					BeaconBlockRoot: rootAB,
					Source:          &eth2p0.Checkpoint{Epoch: 999, Root: rootCD},
					Target:          &eth2p0.Checkpoint{Epoch: 1000, Root: rootEF},
				},
				Duty: eth2v1.AttesterDuty{
					PubKey:                  pubKey01,
					Slot:                    4294967295,
					ValidatorIndex:          1000000,
					CommitteeIndex:          511,
					CommitteeLength:         1024,
					CommitteesAtSlot:        512,
					ValidatorCommitteeIndex: 255,
				},
			},
			// Slot=4294967295=0xFFFFFFFF, Index=255=0xFF, epochs 999/1000,
			// ValidatorIndex=1000000=0xF4240, CommitteeIndex=511=0x1FF,
			// CommitteeLength=1024=0x400, CommitteesAtSlot=512=0x200.
			expected: "0x0800000088000000" +
				"ffffffff00000000" + // Data.Slot = 4294967295
				"ff00000000000000" + // Data.Index = 255
				strings.Repeat("ab", 32) + // BeaconBlockRoot
				"e703000000000000" + // Source.Epoch = 999 (0x3E7 LE)
				strings.Repeat("cd", 32) + // Source.Root
				"e803000000000000" + // Target.Epoch = 1000 (0x3E8 LE)
				strings.Repeat("ef", 32) + // Target.Root
				strings.Repeat("01", 48) + // PubKey (all 0x01)
				"ffffffff00000000" + // Duty.Slot = 4294967295
				"40420f0000000000" + // Duty.ValidatorIndex = 1000000 (0xF4240 LE)
				"ff01000000000000" + // Duty.CommitteeIndex = 511 (0x1FF LE)
				"0004000000000000" + // Duty.CommitteeLength = 1024 (0x400 LE)
				"0002000000000000" + // Duty.CommitteesAtSlot = 512 (0x200 LE)
				"ff00000000000000", // Duty.ValidatorCommitteeIndex = 255
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.value.MarshalSSZ()
			require.NoError(t, err)
			require.Equal(t, tt.expected, fmt.Sprintf("%#x", b))

			var got core.AttestationData
			require.NoError(t, got.UnmarshalSSZ(b))
			require.Equal(t, tt.value, got)
		})
	}
}

func TestVersionedAttestationSSZ(t *testing.T) {
	phase0Att := &eth2p0.Attestation{
		AggregationBits: bitfield.Bitlist{0x01},
		Data: &eth2p0.AttestationData{
			Source: new(eth2p0.Checkpoint),
			Target: new(eth2p0.Checkpoint),
		},
	}

	electraAtt := &electra.Attestation{
		AggregationBits: bitfield.Bitlist{0x01},
		Data: &eth2p0.AttestationData{
			Source: new(eth2p0.Checkpoint),
			Target: new(eth2p0.Checkpoint),
		},
		CommitteeBits: bitfield.Bitvector64(make([]byte, 8)),
	}

	v0 := eth2p0.ValidatorIndex(0)
	v42 := eth2p0.ValidatorIndex(42)
	v999 := eth2p0.ValidatorIndex(999)

	// phase0AttSSZ is the inner SSZ of a minimal phase0.Attestation (229 bytes):
	// AggBitsOffset(4) + Data(128) + Signature(96) + AggBits(1).
	phase0AttSSZ := "e4000000" + // AggBits offset=228 within attestation
		strings.Repeat("00", 128) + // Data (zero)
		strings.Repeat("00", 96) + // Signature (zero)
		"01" // AggBits={0x01}

	// electraAttSSZ is the inner SSZ of a minimal electra.Attestation (237 bytes):
	// AggBitsOffset(4) + Data(128) + CommitteeBits(8) + Signature(96) + AggBits(1).
	electraAttSSZ := "ec000000" + // AggBits offset=236 within attestation
		strings.Repeat("00", 128) + // Data (zero)
		strings.Repeat("00", 8) + // CommitteeBits (zero)
		strings.Repeat("00", 96) + // Signature (zero)
		"01" // AggBits={0x01}

	tests := []struct {
		name     string
		value    core.VersionedAttestation
		expected string
	}{
		{
			name:  "phase0_zeros",
			value: core.VersionedAttestation{VersionedAttestation: eth2spec.VersionedAttestation{Version: eth2spec.DataVersionPhase0, Phase0: phase0Att}},
			// version(8) + offset=12(4) + phase0 attestation(229)
			expected: "0x" +
				"0000000000000000" + // version=0 (phase0)
				"0c000000" + // outer offset=12
				phase0AttSSZ,
		},
		{
			name:  "electra_zeros",
			value: core.VersionedAttestation{VersionedAttestation: eth2spec.VersionedAttestation{Version: eth2spec.DataVersionElectra, Electra: electraAtt}},
			// version(8) + offset=12(4) + electra attestation(237)
			expected: "0x" +
				"0500000000000000" + // version=5 (electra)
				"0c000000" + // outer offset=12
				electraAttSSZ,
		},
		{
			name:  "fulu_zeros",
			value: core.VersionedAttestation{VersionedAttestation: eth2spec.VersionedAttestation{Version: eth2spec.DataVersionFulu, Fulu: electraAtt}},
			expected: "0x" +
				"0600000000000000" + // version=6 (fulu)
				"0c000000" +
				electraAttSSZ,
		},
		{
			name: "phase0_non_zero",
			// Slot=1000, Index=5, Source.Epoch=10, Target.Epoch=11, AggBits={0x03}.
			value: core.VersionedAttestation{VersionedAttestation: eth2spec.VersionedAttestation{
				Version: eth2spec.DataVersionPhase0,
				Phase0: &eth2p0.Attestation{
					AggregationBits: bitfield.Bitlist{0x03},
					Data: &eth2p0.AttestationData{
						Slot:   1000,
						Index:  5,
						Source: &eth2p0.Checkpoint{Epoch: 10},
						Target: &eth2p0.Checkpoint{Epoch: 11},
					},
				},
			}},
			expected: "0x" +
				"0000000000000000" + // version=0
				"0c000000" + // outer offset=12
				"e4000000" + // AggBits offset=228
				"e803000000000000" + // Data.Slot=1000 (0x3E8 LE)
				"0500000000000000" + // Data.Index=5
				strings.Repeat("00", 32) + // BeaconBlockRoot (zero)
				"0a00000000000000" + // Source.Epoch=10 (0x0A LE)
				strings.Repeat("00", 32) + // Source.Root (zero)
				"0b00000000000000" + // Target.Epoch=11 (0x0B LE)
				strings.Repeat("00", 32) + // Target.Root (zero)
				strings.Repeat("00", 96) + // Signature (zero)
				"03", // AggBits={0x03}
		},
		{
			name: "electra_non_zero",
			// Slot=2000, Index=3, Source.Epoch=20, Target.Epoch=21, AggBits={0x07}.
			value: core.VersionedAttestation{VersionedAttestation: eth2spec.VersionedAttestation{
				Version: eth2spec.DataVersionElectra,
				Electra: &electra.Attestation{
					AggregationBits: bitfield.Bitlist{0x07},
					Data: &eth2p0.AttestationData{
						Slot:   2000,
						Index:  3,
						Source: &eth2p0.Checkpoint{Epoch: 20},
						Target: &eth2p0.Checkpoint{Epoch: 21},
					},
					CommitteeBits: bitfield.Bitvector64(make([]byte, 8)),
				},
			}},
			expected: "0x" +
				"0500000000000000" + // version=5
				"0c000000" +
				"ec000000" + // AggBits offset=236
				"d007000000000000" + // Data.Slot=2000 (0x7D0 LE)
				"0300000000000000" + // Data.Index=3
				strings.Repeat("00", 32) +
				"1400000000000000" + // Source.Epoch=20 (0x14 LE)
				strings.Repeat("00", 32) +
				"1500000000000000" + // Target.Epoch=21 (0x15 LE)
				strings.Repeat("00", 32) +
				strings.Repeat("00", 8) + // CommitteeBits (zero)
				strings.Repeat("00", 96) +
				"07", // AggBits={0x07}
		},
		{
			name:  "phase0_valIdx0",
			value: core.VersionedAttestation{VersionedAttestation: eth2spec.VersionedAttestation{Version: eth2spec.DataVersionPhase0, Phase0: phase0Att, ValidatorIndex: &v0}},
			// version(8) + valIdx=0(8) + offset=20(4) + phase0 attestation(229)
			expected: "0x" +
				"0000000000000000" + // version=0
				"0000000000000000" + // valIdx=0
				"14000000" + // outer offset=20
				phase0AttSSZ,
		},
		{
			name:  "phase0_valIdx42",
			value: core.VersionedAttestation{VersionedAttestation: eth2spec.VersionedAttestation{Version: eth2spec.DataVersionPhase0, Phase0: phase0Att, ValidatorIndex: &v42}},
			// version(8) + valIdx=42(8) + offset=20(4) + phase0 attestation(229)
			expected: "0x" +
				"0000000000000000" + // version=0
				"2a00000000000000" + // valIdx=42 (0x2A LE)
				"14000000" + // outer offset=20
				phase0AttSSZ,
		},
		{
			name:  "electra_valIdx999",
			value: core.VersionedAttestation{VersionedAttestation: eth2spec.VersionedAttestation{Version: eth2spec.DataVersionElectra, Electra: electraAtt, ValidatorIndex: &v999}},
			// version(8) + valIdx=999(8) + offset=20(4) + electra attestation(237)
			expected: "0x" +
				"0500000000000000" + // version=5
				"e703000000000000" + // valIdx=999 (0x3E7 LE)
				"14000000" + // outer offset=20
				electraAttSSZ,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.value.MarshalSSZ()
			require.NoError(t, err)
			require.Equal(t, tt.expected, fmt.Sprintf("%#x", b))

			var got core.VersionedAttestation
			require.NoError(t, got.UnmarshalSSZ(b))
			require.Equal(t, tt.value, got)
		})
	}
}

func TestVersionedAggregatedAttestationSSZ(t *testing.T) {
	phase0Att := &eth2p0.Attestation{
		AggregationBits: bitfield.Bitlist{0x01},
		Data: &eth2p0.AttestationData{
			Source: new(eth2p0.Checkpoint),
			Target: new(eth2p0.Checkpoint),
		},
	}

	electraAtt := &electra.Attestation{
		AggregationBits: bitfield.Bitlist{0x01},
		Data: &eth2p0.AttestationData{
			Source: new(eth2p0.Checkpoint),
			Target: new(eth2p0.Checkpoint),
		},
		CommitteeBits: bitfield.Bitvector64(make([]byte, 8)),
	}

	phase0AttSSZ := "e4000000" + strings.Repeat("00", 128) + strings.Repeat("00", 96) + "01"
	electraAttSSZ := "ec000000" + strings.Repeat("00", 128) + strings.Repeat("00", 8) + strings.Repeat("00", 96) + "01"

	tests := []struct {
		name     string
		value    core.VersionedAggregatedAttestation
		expected string
	}{
		{
			name:  "phase0_zeros",
			value: core.VersionedAggregatedAttestation{VersionedAttestation: eth2spec.VersionedAttestation{Version: eth2spec.DataVersionPhase0, Phase0: phase0Att}},
			expected: "0x" +
				"0000000000000000" + // version=0 (phase0)
				"0c000000" + // offset=12
				phase0AttSSZ,
		},
		{
			name:  "electra_zeros",
			value: core.VersionedAggregatedAttestation{VersionedAttestation: eth2spec.VersionedAttestation{Version: eth2spec.DataVersionElectra, Electra: electraAtt}},
			expected: "0x" +
				"0500000000000000" + // version=5 (electra)
				"0c000000" +
				electraAttSSZ,
		},
		{
			name:  "fulu_zeros",
			value: core.VersionedAggregatedAttestation{VersionedAttestation: eth2spec.VersionedAttestation{Version: eth2spec.DataVersionFulu, Fulu: electraAtt}},
			expected: "0x" +
				"0600000000000000" + // version=6 (fulu)
				"0c000000" +
				electraAttSSZ,
		},
		{
			name: "phase0_non_zero",
			// Slot=1000, Index=5, Source.Epoch=10, Target.Epoch=11.
			value: core.VersionedAggregatedAttestation{VersionedAttestation: eth2spec.VersionedAttestation{
				Version: eth2spec.DataVersionPhase0,
				Phase0: &eth2p0.Attestation{
					AggregationBits: bitfield.Bitlist{0x03},
					Data: &eth2p0.AttestationData{
						Slot:   1000,
						Index:  5,
						Source: &eth2p0.Checkpoint{Epoch: 10},
						Target: &eth2p0.Checkpoint{Epoch: 11},
					},
				},
			}},
			expected: "0x" +
				"0000000000000000" +
				"0c000000" +
				"e4000000" +
				"e803000000000000" + // Slot=1000
				"0500000000000000" + // Index=5
				strings.Repeat("00", 32) +
				"0a00000000000000" + // Source.Epoch=10
				strings.Repeat("00", 32) +
				"0b00000000000000" + // Target.Epoch=11
				strings.Repeat("00", 32) +
				strings.Repeat("00", 96) +
				"03", // AggBits={0x03}
		},
		{
			name: "electra_non_zero",
			// Slot=2000, Index=3, Source.Epoch=20, Target.Epoch=21.
			value: core.VersionedAggregatedAttestation{VersionedAttestation: eth2spec.VersionedAttestation{
				Version: eth2spec.DataVersionElectra,
				Electra: &electra.Attestation{
					AggregationBits: bitfield.Bitlist{0x07},
					Data: &eth2p0.AttestationData{
						Slot:   2000,
						Index:  3,
						Source: &eth2p0.Checkpoint{Epoch: 20},
						Target: &eth2p0.Checkpoint{Epoch: 21},
					},
					CommitteeBits: bitfield.Bitvector64(make([]byte, 8)),
				},
			}},
			expected: "0x" +
				"0500000000000000" +
				"0c000000" +
				"ec000000" +
				"d007000000000000" + // Slot=2000
				"0300000000000000" + // Index=3
				strings.Repeat("00", 32) +
				"1400000000000000" + // Source.Epoch=20
				strings.Repeat("00", 32) +
				"1500000000000000" + // Target.Epoch=21
				strings.Repeat("00", 32) +
				strings.Repeat("00", 8) +
				strings.Repeat("00", 96) +
				"07", // AggBits={0x07}
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.value.MarshalSSZ()
			require.NoError(t, err)
			require.Equal(t, tt.expected, fmt.Sprintf("%#x", b))

			var got core.VersionedAggregatedAttestation
			require.NoError(t, got.UnmarshalSSZ(b))
			require.Equal(t, tt.value, got)
		})
	}
}

func TestVersionedSignedAggregateAndProofSSZ(t *testing.T) {
	phase0Att := &eth2p0.Attestation{
		AggregationBits: bitfield.Bitlist{0x01},
		Data: &eth2p0.AttestationData{
			Source: new(eth2p0.Checkpoint),
			Target: new(eth2p0.Checkpoint),
		},
	}

	electraAtt := &electra.Attestation{
		AggregationBits: bitfield.Bitlist{0x01},
		Data: &eth2p0.AttestationData{
			Source: new(eth2p0.Checkpoint),
			Target: new(eth2p0.Checkpoint),
		},
		CommitteeBits: bitfield.Bitvector64(make([]byte, 8)),
	}

	saapPrefix := "64000000" + // Message offset=100 within SAAP
		strings.Repeat("00", 96) // Signature (zero)

	aapPrefixZero := "0000000000000000" + // AggregatorIndex=0
		"6c000000" + // Aggregate offset=108 within AAP
		strings.Repeat("00", 96) // SelectionProof (zero)

	phase0AttSSZ := "e4000000" + strings.Repeat("00", 128) + strings.Repeat("00", 96) + "01"
	electraAttSSZ := "ec000000" + strings.Repeat("00", 128) + strings.Repeat("00", 8) + strings.Repeat("00", 96) + "01"

	tests := []struct {
		name     string
		value    core.VersionedSignedAggregateAndProof
		expected string
	}{
		{
			name:  "phase0_zeros",
			value: core.VersionedSignedAggregateAndProof{VersionedSignedAggregateAndProof: eth2spec.VersionedSignedAggregateAndProof{Version: eth2spec.DataVersionPhase0, Phase0: &eth2p0.SignedAggregateAndProof{Message: &eth2p0.AggregateAndProof{Aggregate: phase0Att}}}},
			// version(8) + offset=12(4) + SignedAggregateAndProof(437)
			expected: "0x" +
				"0000000000000000" + // version=0 (phase0)
				"0c000000" + // outer offset=12
				saapPrefix + aapPrefixZero + phase0AttSSZ,
		},
		{
			name:  "electra_zeros",
			value: core.VersionedSignedAggregateAndProof{VersionedSignedAggregateAndProof: eth2spec.VersionedSignedAggregateAndProof{Version: eth2spec.DataVersionElectra, Electra: &electra.SignedAggregateAndProof{Message: &electra.AggregateAndProof{Aggregate: electraAtt}}}},
			// version(8) + offset=12(4) + SignedAggregateAndProof(445)
			expected: "0x" +
				"0500000000000000" + // version=5 (electra)
				"0c000000" +
				saapPrefix + aapPrefixZero + electraAttSSZ,
		},
		{
			name:  "fulu_zeros",
			value: core.VersionedSignedAggregateAndProof{VersionedSignedAggregateAndProof: eth2spec.VersionedSignedAggregateAndProof{Version: eth2spec.DataVersionFulu, Fulu: &electra.SignedAggregateAndProof{Message: &electra.AggregateAndProof{Aggregate: electraAtt}}}},
			expected: "0x" +
				"0600000000000000" + // version=6 (fulu)
				"0c000000" +
				saapPrefix + aapPrefixZero + electraAttSSZ,
		},
		{
			name:  "deneb_zeros",
			value: core.VersionedSignedAggregateAndProof{VersionedSignedAggregateAndProof: eth2spec.VersionedSignedAggregateAndProof{Version: eth2spec.DataVersionDeneb, Deneb: &eth2p0.SignedAggregateAndProof{Message: &eth2p0.AggregateAndProof{Aggregate: phase0Att}}}},
			expected: "0x" +
				"0400000000000000" + // version=4 (deneb)
				"0c000000" +
				saapPrefix + aapPrefixZero + phase0AttSSZ,
		},
		{
			name: "phase0_aggregator_index_7",
			value: core.VersionedSignedAggregateAndProof{VersionedSignedAggregateAndProof: eth2spec.VersionedSignedAggregateAndProof{
				Version: eth2spec.DataVersionPhase0,
				Phase0: &eth2p0.SignedAggregateAndProof{
					Message: &eth2p0.AggregateAndProof{
						AggregatorIndex: 7,
						Aggregate: &eth2p0.Attestation{
							AggregationBits: bitfield.Bitlist{0x03},
							Data: &eth2p0.AttestationData{
								Slot:   1000,
								Index:  5,
								Source: &eth2p0.Checkpoint{Epoch: 10},
								Target: &eth2p0.Checkpoint{Epoch: 11},
							},
						},
					},
				},
			}},
			expected: "0x" +
				"0000000000000000" + // version=0
				"0c000000" + // outer offset=12
				saapPrefix + // SAAP fixed region
				"0700000000000000" + // AggregatorIndex=7
				"6c000000" + // Aggregate offset=108
				strings.Repeat("00", 96) + // SelectionProof (zero)
				"e4000000" + // AggBits offset=228
				"e803000000000000" + // Data.Slot=1000
				"0500000000000000" + // Data.Index=5
				strings.Repeat("00", 32) + // BeaconBlockRoot
				"0a00000000000000" + // Source.Epoch=10
				strings.Repeat("00", 32) + // Source.Root
				"0b00000000000000" + // Target.Epoch=11
				strings.Repeat("00", 32) + // Target.Root
				strings.Repeat("00", 96) + // Att.Signature
				"03", // AggBits={0x03}
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.value.MarshalSSZ()
			require.NoError(t, err)
			require.Equal(t, tt.expected, fmt.Sprintf("%#x", b))

			var got core.VersionedSignedAggregateAndProof
			require.NoError(t, got.UnmarshalSSZ(b))
			require.Equal(t, tt.value, got)
		})
	}
}

func TestVersionedSignedProposalSSZ(t *testing.T) {
	phase0Block := &eth2p0.SignedBeaconBlock{
		Message: &eth2p0.BeaconBlock{
			Body: &eth2p0.BeaconBlockBody{
				ETH1Data: new(eth2p0.ETH1Data),
			},
		},
	}

	altairBlock := &altair.SignedBeaconBlock{
		Message: &altair.BeaconBlock{
			Body: &altair.BeaconBlockBody{
				ETH1Data: new(eth2p0.ETH1Data),
				SyncAggregate: &altair.SyncAggregate{
					SyncCommitteeBits: bitfield.Bitvector512(make([]byte, 64)),
				},
			},
		},
	}

	electraBlindedBlock := &eth2electra.SignedBlindedBeaconBlock{
		Message: &eth2electra.BlindedBeaconBlock{
			Body: &eth2electra.BlindedBeaconBlockBody{
				ETH1Data: new(eth2p0.ETH1Data),
				SyncAggregate: &altair.SyncAggregate{
					SyncCommitteeBits: bitfield.Bitvector512(make([]byte, 64)),
				},
				ExecutionPayloadHeader: new(deneb.ExecutionPayloadHeader),
				ExecutionRequests:      new(electra.ExecutionRequests),
			},
		},
	}

	denebBlock := &eth2deneb.SignedBlockContents{
		SignedBlock: &deneb.SignedBeaconBlock{
			Message: &deneb.BeaconBlock{
				Body: &deneb.BeaconBlockBody{
					ETH1Data: new(eth2p0.ETH1Data),
					SyncAggregate: &altair.SyncAggregate{
						SyncCommitteeBits: bitfield.Bitvector512(make([]byte, 64)),
					},
					ExecutionPayload: &deneb.ExecutionPayload{},
				},
			},
		},
	}

	tests := []struct {
		name     string
		apiProp  eth2api.VersionedSignedProposal
		expected string
	}{
		{
			name:    "phase0",
			apiProp: eth2api.VersionedSignedProposal{Version: eth2spec.DataVersionPhase0, Phase0: phase0Block},
			// Header: version=0, blinded=false, offset=13. Inner=phase0.SignedBeaconBlock (404 bytes).
			expected: "0x0000000000000000000d000000640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000540000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000dc000000dc000000dc000000dc000000dc000000",
		},
		{
			name:    "altair",
			apiProp: eth2api.VersionedSignedProposal{Version: eth2spec.DataVersionAltair, Altair: altairBlock},
			// Header: version=1, blinded=false, offset=13. Inner=altair.SignedBeaconBlock (564 bytes).
			expected: "0x0100000000000000000d0000006400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007c0100007c0100007c0100007c0100007c01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:    "electra_blinded",
			apiProp: eth2api.VersionedSignedProposal{Version: eth2spec.DataVersionElectra, ElectraBlinded: electraBlindedBlock, Blinded: true},
			// Header: version=5, blinded=true, offset=13.
			expected: "0x0500000000000000010d0000006400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008c0100008c0100008c0100008c0100008c010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008c010000d4030000d4030000d403000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000480200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0000000c0000000c000000",
		},
		{
			name:    "fulu_blinded",
			apiProp: eth2api.VersionedSignedProposal{Version: eth2spec.DataVersionFulu, FuluBlinded: electraBlindedBlock, Blinded: true},
			// Header: version=6, blinded=true, offset=13. Inner same structure as electra_blinded.
			expected: "0x0600000000000000010d0000006400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008c0100008c0100008c0100008c0100008c010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008c010000d4030000d4030000d403000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000480200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0000000c0000000c000000",
		},
		{
			name:    "deneb",
			apiProp: eth2api.VersionedSignedProposal{Version: eth2spec.DataVersionDeneb, Deneb: denebBlock},
			// Header: version=4, blinded=false, offset=13. Inner=eth2deneb.SignedBlockContents (1116 bytes).
			expected: "0x0400000000000000000d0000000c0000005c0400005c040000640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000540000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000880100008801000088010000880100008801000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000880100009803000098030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100200001002000000000000000000000000000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := core.NewVersionedSignedProposal(&tt.apiProp)
			require.NoError(t, err)

			b, err := p.MarshalSSZ()
			require.NoError(t, err)
			require.Equal(t, tt.expected, fmt.Sprintf("%#x", b))

			p2 := new(core.VersionedSignedProposal)
			require.NoError(t, p2.UnmarshalSSZ(b))
		})
	}
}

func TestVersionedProposalSSZ(t *testing.T) {
	phase0Block := &eth2p0.BeaconBlock{
		Body: &eth2p0.BeaconBlockBody{
			ETH1Data: new(eth2p0.ETH1Data),
		},
	}

	altairBlock := &altair.BeaconBlock{
		Body: &altair.BeaconBlockBody{
			ETH1Data: new(eth2p0.ETH1Data),
			SyncAggregate: &altair.SyncAggregate{
				SyncCommitteeBits: bitfield.Bitvector512(make([]byte, 64)),
			},
		},
	}

	electraBlindedBlock := &eth2electra.BlindedBeaconBlock{
		Body: &eth2electra.BlindedBeaconBlockBody{
			ETH1Data: new(eth2p0.ETH1Data),
			SyncAggregate: &altair.SyncAggregate{
				SyncCommitteeBits: bitfield.Bitvector512(make([]byte, 64)),
			},
			ExecutionPayloadHeader: new(deneb.ExecutionPayloadHeader),
			ExecutionRequests:      new(electra.ExecutionRequests),
		},
	}

	denebBlock := &eth2deneb.BlockContents{
		Block: &deneb.BeaconBlock{
			Body: &deneb.BeaconBlockBody{
				ETH1Data: new(eth2p0.ETH1Data),
				SyncAggregate: &altair.SyncAggregate{
					SyncCommitteeBits: bitfield.Bitvector512(make([]byte, 64)),
				},
				ExecutionPayload: &deneb.ExecutionPayload{},
			},
		},
	}

	tests := []struct {
		name     string
		apiProp  eth2api.VersionedProposal
		expected string
	}{
		{
			name:    "phase0",
			apiProp: eth2api.VersionedProposal{Version: eth2spec.DataVersionPhase0, Phase0: phase0Block},
			// Header: version=0, blinded=false, offset=13. Inner=phase0.BeaconBlock (304 bytes).
			expected: "0x0000000000000000000d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000540000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000dc000000dc000000dc000000dc000000dc000000",
		},
		{
			name:    "altair",
			apiProp: eth2api.VersionedProposal{Version: eth2spec.DataVersionAltair, Altair: altairBlock},
			// Header: version=1, blinded=false, offset=13. Inner=altair.BeaconBlock (464 bytes).
			expected: "0x0100000000000000000d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007c0100007c0100007c0100007c0100007c01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:    "electra_blinded",
			apiProp: eth2api.VersionedProposal{Version: eth2spec.DataVersionElectra, ElectraBlinded: electraBlindedBlock, Blinded: true},
			// Header: version=5, blinded=true, offset=13.
			expected: "0x0500000000000000010d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008c0100008c0100008c0100008c0100008c010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008c010000d4030000d4030000d403000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000480200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0000000c0000000c000000",
		},
		{
			name:    "fulu_blinded",
			apiProp: eth2api.VersionedProposal{Version: eth2spec.DataVersionFulu, FuluBlinded: electraBlindedBlock, Blinded: true},
			// Header: version=6, blinded=true, offset=13. Inner same structure as electra_blinded.
			expected: "0x0600000000000000010d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008c0100008c0100008c0100008c0100008c010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008c010000d4030000d4030000d403000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000480200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0000000c0000000c000000",
		},
		{
			name:    "deneb",
			apiProp: eth2api.VersionedProposal{Version: eth2spec.DataVersionDeneb, Deneb: denebBlock},
			// Header: version=4, blinded=false, offset=13. Inner=eth2deneb.BlockContents (1016 bytes).
			expected: "0x0400000000000000000d0000000c000000f8030000f80300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000540000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000880100008801000088010000880100008801000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000880100009803000098030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100200001002000000000000000000000000000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := core.NewVersionedProposal(&tt.apiProp)
			require.NoError(t, err)

			b, err := p.MarshalSSZ()
			require.NoError(t, err)
			require.Equal(t, tt.expected, fmt.Sprintf("%#x", b))

			p2 := new(core.VersionedProposal)
			require.NoError(t, p2.UnmarshalSSZ(b))
		})
	}
}
