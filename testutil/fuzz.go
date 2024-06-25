// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package testutil

import (
	"math/rand"
	"testing"
	"time"

	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	fuzz "github.com/google/gofuzz"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
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
		eth2spec.DataVersionDeneb,
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
			// eth2p0.AttesterSlashings has max
			func(e *[]*eth2p0.AttesterSlashing, c fuzz.Continue) {
				c.FuzzNoCustom(e)
				if len(*e) > 2 {
					*e = (*e)[:2]
				}
			},
			// eth2p0.ProposerSlashings has max
			func(e *[]*eth2p0.ProposerSlashing, c fuzz.Continue) {
				c.FuzzNoCustom(e)
				if len(*e) > 16 {
					*e = (*e)[:16]
				}
			},
			// Eth1Data.BlockHash must be 32 bytes
			func(e *eth2p0.ETH1Data, c fuzz.Continue) {
				c.FuzzNoCustom(e)

				var blockHash [32]byte
				_, _ = c.Read(blockHash[:])
				e.BlockHash = blockHash[:]
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
			// []deneb.KzgCommitment has max.
			func(e *[]deneb.KZGCommitment, c fuzz.Continue) {
				c.FuzzNoCustom(e)
				if len(*e) > 4 {
					*e = (*e)[:4]
				}
			},
			// Populate one of the versions of these VersionedSignedProposal types.
			func(e *core.VersionedSignedProposal, c fuzz.Continue) {
				e.Version = allVersions[(c.Intn(len(allVersions)))]
				if e.Blinded {
					e.Version = blindedVersions[(c.Intn(len(blindedVersions)))]
				}

				version, err := eth2util.DataVersionFromETH2(e.Version)
				require.NoError(t, err)

				val := core.VersionedSSZValueForT(t, e, version, e.Blinded)
				c.Fuzz(val)

				// Limit length of KZGProofs and Blobs to 6
				// See https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/beacon-chain.md#execution
				maxKZGProofs := 6
				if e.Version == eth2spec.DataVersionDeneb && len(e.Deneb.KZGProofs) > maxKZGProofs {
					e.Deneb.KZGProofs = e.Deneb.KZGProofs[:maxKZGProofs]
				}

				maxBlobs := 6
				if e.Version == eth2spec.DataVersionDeneb && len(e.Deneb.Blobs) > maxBlobs {
					e.Deneb.Blobs = e.Deneb.Blobs[:maxBlobs]
				}

				maxBlobCommitments := 4096
				if e.Version == eth2spec.DataVersionDeneb && len(e.DenebBlinded.Message.Body.BlobKZGCommitments) > maxBlobCommitments {
					e.DenebBlinded.Message.Body.BlobKZGCommitments = e.DenebBlinded.Message.Body.BlobKZGCommitments[:maxBlobCommitments]
				}
			},
			func(e *core.VersionedProposal, c fuzz.Continue) {
				e.Version = allVersions[(c.Intn(len(allVersions)))]
				version, err := eth2util.DataVersionFromETH2(e.Version)
				require.NoError(t, err)

				val := core.VersionedSSZValueForT(t, e, version, false)
				c.Fuzz(val)

				// Limit length of KZGProofs and Blobs to 6
				// See https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/beacon-chain.md#execution
				maxKZGProofs := 6
				if e.Version == eth2spec.DataVersionDeneb && len(e.Deneb.KZGProofs) > maxKZGProofs {
					e.Deneb.KZGProofs = e.Deneb.KZGProofs[:maxKZGProofs]
				}
				maxBlobs := 6
				if e.Version == eth2spec.DataVersionDeneb && len(e.Deneb.Blobs) > maxBlobs {
					e.Deneb.Blobs = e.Deneb.Blobs[:maxBlobs]
				}
			},
		)
}
