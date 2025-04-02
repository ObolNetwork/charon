// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package testutil

import (
	"math/rand"
	"testing"
	"time"

	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
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
// Note go-eth2-client Versioned*Blocks are not supported, instead use core.Versioned*Blocks.
func NewEth2Fuzzer(t *testing.T, seed int64) *fuzz.Fuzzer {
	t.Helper()

	blindedVersions := []eth2spec.DataVersion{
		eth2spec.DataVersionBellatrix,
		eth2spec.DataVersionCapella,
		eth2spec.DataVersionDeneb,
		eth2spec.DataVersionElectra,
	}

	allVersions := []eth2spec.DataVersion{
		eth2spec.DataVersionPhase0,
		eth2spec.DataVersionAltair,
		eth2spec.DataVersionBellatrix,
		eth2spec.DataVersionCapella,
		eth2spec.DataVersionDeneb,
		eth2spec.DataVersionElectra,
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
			func(e *[]*eth2p0.Deposit, _ fuzz.Continue) {
				*e = []*eth2p0.Deposit{}
			},
			// SyncAggregate.SyncCommitteeBits must have 64 bits
			func(e *altair.SyncAggregate, c fuzz.Continue) {
				c.FuzzNoCustom(e)
				bits := bitfield.NewBitvector512()
				for i := range 64 {
					bits.SetBitAt(uint64(i), true)
				}
				e.SyncCommitteeBits = bits
			},
			// SyncCommitteeContribution.AggregationBits must have 16 bits
			func(e *altair.SyncCommitteeContribution, c fuzz.Continue) {
				c.FuzzNoCustom(e)
				bits := bitfield.NewBitvector128()
				for i := range 16 {
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
			// electra.ExecutionRequests has max.
			func(e *electra.ExecutionRequests, c fuzz.Continue) {
				c.FuzzNoCustom(e)
				bits := bitfield.NewBitvector256()
				for i := range 32 {
					bits.SetBitAt(uint64(i), true)
				}
				for idx := range e.Deposits {
					e.Deposits[idx].WithdrawalCredentials = bits
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

				val := core.VersionedBlindedSSZValueForT(t, e, version, e.Blinded)
				c.Fuzz(val)

				var (
					maxKZGProofs       = 6
					maxBlobs           = 6
					maxBlobCommitments = 4096
				)

				if e.Version == eth2spec.DataVersionDeneb {
					if e.Deneb != nil {
						// Limit length of KZGProofs to 6
						if len(e.Deneb.KZGProofs) > maxKZGProofs {
							e.Deneb.KZGProofs = e.Deneb.KZGProofs[:maxKZGProofs]
						}

						// Limit length of Blobs to 6
						if len(e.Deneb.Blobs) > maxBlobs {
							e.Deneb.Blobs = e.Deneb.Blobs[:maxBlobs]
						}
					}

					if e.DenebBlinded != nil {
						// Limit length of BlobKZGCommitments to 6
						if len(e.DenebBlinded.Message.Body.BlobKZGCommitments) > maxBlobCommitments {
							e.DenebBlinded.Message.Body.BlobKZGCommitments = e.DenebBlinded.Message.Body.BlobKZGCommitments[:maxBlobCommitments]
						}
					}
				}
				if e.Version == eth2spec.DataVersionElectra {
					if e.Electra != nil {
						// Limit length of KZGProofs to 6
						if len(e.Electra.KZGProofs) > maxKZGProofs {
							e.Electra.KZGProofs = e.Electra.KZGProofs[:maxKZGProofs]
						}
						// Limit length of Blobs to 6
						if len(e.Electra.Blobs) > maxBlobs {
							e.Electra.Blobs = e.Electra.Blobs[:maxBlobs]
						}
						// Limit ExecutionRequests.Consolidations to 2
						if len(e.Electra.SignedBlock.Message.Body.ExecutionRequests.Consolidations) > 2 {
							// Limit length of BlobKZGCommitments to 6
							e.Electra.SignedBlock.Message.Body.ExecutionRequests.Consolidations = e.Electra.SignedBlock.Message.Body.ExecutionRequests.Consolidations[:2]
						}
						// Limit Attestations to 8
						// https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.3/specs/electra/beacon-chain.md#max-operations-per-block
						if len(e.Electra.SignedBlock.Message.Body.Attestations) > 8 {
							e.Electra.SignedBlock.Message.Body.Attestations = e.Electra.SignedBlock.Message.Body.Attestations[:8]
						}
						// Limit AttesterSlashings to 1
						// https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.3/specs/electra/beacon-chain.md#max-operations-per-block
						if len(e.Electra.SignedBlock.Message.Body.AttesterSlashings) > 1 {
							e.Electra.SignedBlock.Message.Body.AttesterSlashings = e.Electra.SignedBlock.Message.Body.AttesterSlashings[:1]
						}
					}

					if e.ElectraBlinded != nil {
						if len(e.ElectraBlinded.Message.Body.BlobKZGCommitments) > maxBlobCommitments {
							// Limit ExecutionRequests.Consolidations to 2
							e.ElectraBlinded.Message.Body.BlobKZGCommitments = e.ElectraBlinded.Message.Body.BlobKZGCommitments[:maxBlobCommitments]
						}
						// Limit ExecutionRequests.Consolidations to 2
						if len(e.ElectraBlinded.Message.Body.ExecutionRequests.Consolidations) > 2 {
							e.ElectraBlinded.Message.Body.ExecutionRequests.Consolidations = e.ElectraBlinded.Message.Body.ExecutionRequests.Consolidations[:2]
						}
						// Limit Attestations to 8
						// https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.3/specs/electra/beacon-chain.md#max-operations-per-block
						if len(e.ElectraBlinded.Message.Body.Attestations) > 8 {
							e.ElectraBlinded.Message.Body.Attestations = e.Electra.SignedBlock.Message.Body.Attestations[:8]
						}
						// Limit AttesterSlashings to 1
						// https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.3/specs/electra/beacon-chain.md#max-operations-per-block
						if len(e.ElectraBlinded.Message.Body.AttesterSlashings) > 1 {
							e.ElectraBlinded.Message.Body.AttesterSlashings = e.Electra.SignedBlock.Message.Body.AttesterSlashings[:1]
						}
					}
				}
			},
			func(e *core.VersionedProposal, c fuzz.Continue) {
				e.Version = allVersions[(c.Intn(len(allVersions)))]
				version, err := eth2util.DataVersionFromETH2(e.Version)
				require.NoError(t, err)

				val := core.VersionedBlindedSSZValueForT(t, e, version, false)
				c.Fuzz(val)

				if e.Version == eth2spec.DataVersionElectra {
					// Limit length of KZGProofs and Blobs to 6
					// See https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/beacon-chain.md#execution
					maxKZGProofs := 6
					maxBlobs := 6
					if e.Version == eth2spec.DataVersionDeneb && len(e.Deneb.KZGProofs) > maxKZGProofs {
						e.Deneb.KZGProofs = e.Deneb.KZGProofs[:maxKZGProofs]
					}
					if e.Version == eth2spec.DataVersionDeneb && len(e.Deneb.Blobs) > maxBlobs {
						e.Deneb.Blobs = e.Deneb.Blobs[:maxBlobs]
					}
				}

				if e.Version == eth2spec.DataVersionElectra {
					// Limit length of KZGProofs and Blobs to 6
					// See https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/beacon-chain.md#execution
					maxKZGProofs := 6
					maxBlobs := 6
					if len(e.Electra.Blobs) > maxBlobs {
						e.Electra.Blobs = e.Electra.Blobs[:maxBlobs]
					}

					if len(e.Electra.KZGProofs) > maxKZGProofs {
						e.Electra.KZGProofs = e.Electra.KZGProofs[:maxKZGProofs]
					}

					// Limit ExecutionRequests.Consolidations to 2
					if len(e.Electra.Block.Body.ExecutionRequests.Consolidations) > 2 {
						e.Electra.Block.Body.ExecutionRequests.Consolidations = e.Electra.Block.Body.ExecutionRequests.Consolidations[:2]
					}
					// Limit Attestations to 8
					// See https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.3/specs/electra/beacon-chain.md#max-operations-per-block
					if len(e.Electra.Block.Body.Attestations) > 8 {
						e.Electra.Block.Body.Attestations = e.Electra.Block.Body.Attestations[:8]
					}
					// Limit AttesterSlashings to 1
					// See https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.3/specs/electra/beacon-chain.md#max-operations-per-block
					if len(e.Electra.Block.Body.AttesterSlashings) > 1 {
						e.Electra.Block.Body.AttesterSlashings = e.Electra.Block.Body.AttesterSlashings[:1]
					}
				}
			},
			func(e *core.VersionedAttestation, c fuzz.Continue) {
				e.Version = allVersions[(c.Intn(len(allVersions)))]
				version, err := eth2util.DataVersionFromETH2(e.Version)
				require.NoError(t, err)

				val := core.VersionedSSZValueForT(t, e, version)
				c.Fuzz(val)
			},
			// electra.AttesterSlashing has max
			func(e *[]*electra.AttesterSlashing, c fuzz.Continue) {
				c.FuzzNoCustom(e)
				if len(*e) > 1 {
					*e = (*e)[:1]
				}
			},
			// electra.Attestation must have 8 bits
			func(e *electra.Attestation, c fuzz.Continue) {
				c.FuzzNoCustom(e)
				bits := bitfield.NewBitvector64()
				for i := range 8 {
					bits.SetBitAt(uint64(i), true)
				}
				e.CommitteeBits = bits
			},
			func(e *core.VersionedAggregatedAttestation, c fuzz.Continue) {
				e.Version = allVersions[(c.Intn(len(allVersions)))]
				version, err := eth2util.DataVersionFromETH2(e.Version)
				require.NoError(t, err)

				val := core.VersionedSSZValueForT(t, e, version)
				c.Fuzz(val)
			},
			func(e *core.VersionedSignedAggregateAndProof, c fuzz.Continue) {
				e.Version = allVersions[(c.Intn(len(allVersions)))]
				version, err := eth2util.DataVersionFromETH2(e.Version)
				require.NoError(t, err)

				val := core.VersionedSSZValueForT(t, e, version)
				c.Fuzz(val)
			},
		)
}
