// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package testutil

import (
	"math/rand"
	"testing"
	"time"

	v1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	fuzz "github.com/google/gofuzz"
	"github.com/prysmaticlabs/go-bitfield"

	"github.com/obolnetwork/charon/core"
)

// NewEth2Fuzzer returns a fuzzer for valid eth2 types using the provided seed,
// unless seed is zero in which case it uses current time.
//
// Note go-eth2-client Versioned*Blocks are not support, instead use core.Versioned*Blocks.
func NewEth2Fuzzer(t *testing.T, seed int64) *fuzz.Fuzzer {
	t.Helper()

	blindedVersions := []eth2spec.DataVersion{
		eth2spec.DataVersionBellatrix,
		eth2spec.DataVersionCapella,
		// eth2spec.DataVersionDeneb,
	}

	allVersions := []eth2spec.DataVersion{
		eth2spec.DataVersionPhase0,
		eth2spec.DataVersionAltair,
		eth2spec.DataVersionBellatrix,
		eth2spec.DataVersionCapella,
		eth2spec.DataVersionDeneb,
	}

	if seed == 0 {
		seed = time.Now().Unix()
	}

	return fuzz.New().
		RandSource(rand.New(rand.NewSource(seed))). //nolint:gosec // Required for deterministic fuzzing.
		NilChance(0).
		Funcs(
			// bitfield.Bitlist trailing byte must not be zero
			func(e *bitfield.Bitlist, c fuzz.Continue) {
				c.FuzzNoCustom(e)
				l := len(*e)
				(*e)[l-1] = 1
			},
			// eth2p0.AttesterSlashings may not be more than 2
			func(e *[]*eth2p0.AttesterSlashing, c fuzz.Continue) {
				c.FuzzNoCustom(e)
				if len(*e) > 2 {
					*e = (*e)[:2]
				}
			},
			// Eth1Data.BlockHash must be 32 bytes
			func(e *eth2p0.ETH1Data, c fuzz.Continue) {
				c.FuzzNoCustom(e)
				e.BlockHash = RandomBytes32()
			},
			// Just zero BeaconBlockBody.Deposits to pass validation.
			func(e *[]*eth2p0.Deposit, c fuzz.Continue) {
				*e = []*eth2p0.Deposit{}
			},
			// SyncAggregate.SyncCommitteeBits must have 64 bits
			func(e *altair.SyncAggregate, c fuzz.Continue) {
				c.FuzzNoCustom(e)
				bits := bitfield.NewBitvector512()
				for i := 0; i < 64; i++ {
					bits.SetBitAt(uint64(i), true)
				}
				e.SyncCommitteeBits = bits
			}, // SyncCommitteeContribution.AggregationBits must have 16 bits
			func(e *altair.SyncCommitteeContribution, c fuzz.Continue) {
				c.FuzzNoCustom(e)
				bits := bitfield.NewBitvector128()
				for i := 0; i < 16; i++ {
					bits.SetBitAt(uint64(i), true)
				}
				e.AggregationBits = bits
			},
			// VersionBlingedBeaconBlock.Deneb SSZ not supported by goeth2client yet, so nil it.
			func(e **v1deneb.BlindedBeaconBlock, c fuzz.Continue) {
				*e = nil
			},
			// []deneb.KzgCommitment has max size 4.
			func(e *[]deneb.KzgCommitment, c fuzz.Continue) {
				c.FuzzNoCustom(e)
				if len(*e) > 4 {
					*e = (*e)[:4]
				}
			},
			// Populate one of the versions of these Versioned*Block types.
			func(e *core.VersionedSignedBlindedBeaconBlock, c fuzz.Continue) {
				e.Version = blindedVersions[(c.Intn(len(blindedVersions)))]
				val := core.VersionedSSZValueForT(t, e, e.Version)
				c.Fuzz(val)
			},
			func(e *core.VersionedBlindedBeaconBlock, c fuzz.Continue) {
				e.Version = blindedVersions[(c.Intn(len(blindedVersions)))]
				val := core.VersionedSSZValueForT(t, e, e.Version)
				c.Fuzz(val)
			},
			func(e *core.VersionedSignedBeaconBlock, c fuzz.Continue) {
				e.Version = allVersions[(c.Intn(len(allVersions)))]
				val := core.VersionedSSZValueForT(t, e, e.Version)
				c.Fuzz(val)
			},
			func(e *core.VersionedBeaconBlock, c fuzz.Continue) {
				e.Version = allVersions[(c.Intn(len(allVersions)))]
				val := core.VersionedSSZValueForT(t, e, e.Version)
				c.Fuzz(val)
			},
		)
}
