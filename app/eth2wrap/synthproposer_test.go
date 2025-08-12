// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestSynthProposer(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		version                       eth2spec.DataVersion
		versionedSignedBlock          *eth2spec.VersionedSignedBeaconBlock
		beaconMockProposalFunc        func(context.Context, *eth2api.ProposalOpts) (*eth2api.VersionedProposal, error)
		populateBlockFunc             func(*eth2api.VersionedProposal) *eth2api.VersionedSignedBlindedProposal
		createVersionedSignedProposal func(*eth2api.VersionedProposal) *eth2api.VersionedSignedProposal
	}{
		{
			version:              eth2spec.DataVersionFulu,
			versionedSignedBlock: testutil.RandomFuluVersionedSignedBeaconBlock(),
			beaconMockProposalFunc: func(_ context.Context, opts *eth2api.ProposalOpts) (*eth2api.VersionedProposal, error) {
				var block *eth2api.VersionedProposal
				if opts.BuilderBoostFactor == nil || *opts.BuilderBoostFactor == 0 {
					block = testutil.RandomFuluVersionedProposal()
					block.Fulu.Block.Slot = opts.Slot
					block.Fulu.Block.Body.RANDAOReveal = opts.RandaoReveal
					block.Fulu.Block.Body.Graffiti = opts.Graffiti
					block.ExecutionValue = big.NewInt(1)
					block.ConsensusValue = big.NewInt(1)
				} else {
					block = &eth2api.VersionedProposal{
						Version:     eth2spec.DataVersionFulu,
						FuluBlinded: testutil.RandomElectraBlindedBeaconBlock(),
					}
					block.FuluBlinded.Slot = opts.Slot
					block.FuluBlinded.Body.RANDAOReveal = opts.RandaoReveal
					block.FuluBlinded.Body.Graffiti = opts.Graffiti
					block.ExecutionValue = big.NewInt(1)
					block.ConsensusValue = big.NewInt(1)
					block.Blinded = true
				}

				return block, nil
			},
			populateBlockFunc: func(block *eth2api.VersionedProposal) *eth2api.VersionedSignedBlindedProposal {
				return &eth2api.VersionedSignedBlindedProposal{
					Version: eth2spec.DataVersionFulu,
					Fulu: &eth2electra.SignedBlindedBeaconBlock{
						Message:   block.FuluBlinded,
						Signature: testutil.RandomEth2Signature(),
					},
				}
			},
			createVersionedSignedProposal: func(block *eth2api.VersionedProposal) *eth2api.VersionedSignedProposal {
				signed := testutil.RandomFuluVersionedSignedProposal()
				signed.Fulu.SignedBlock.Message = block.Fulu.Block

				return signed
			},
		},
		{
			version:              eth2spec.DataVersionElectra,
			versionedSignedBlock: testutil.RandomElectraVersionedSignedBeaconBlock(),
			beaconMockProposalFunc: func(_ context.Context, opts *eth2api.ProposalOpts) (*eth2api.VersionedProposal, error) {
				var block *eth2api.VersionedProposal
				if opts.BuilderBoostFactor == nil || *opts.BuilderBoostFactor == 0 {
					block = testutil.RandomElectraVersionedProposal()
					block.Electra.Block.Slot = opts.Slot
					block.Electra.Block.Body.RANDAOReveal = opts.RandaoReveal
					block.Electra.Block.Body.Graffiti = opts.Graffiti
					block.ExecutionValue = big.NewInt(1)
					block.ConsensusValue = big.NewInt(1)
				} else {
					block = &eth2api.VersionedProposal{
						Version:        eth2spec.DataVersionElectra,
						ElectraBlinded: testutil.RandomElectraBlindedBeaconBlock(),
					}
					block.ElectraBlinded.Slot = opts.Slot
					block.ElectraBlinded.Body.RANDAOReveal = opts.RandaoReveal
					block.ElectraBlinded.Body.Graffiti = opts.Graffiti
					block.ExecutionValue = big.NewInt(1)
					block.ConsensusValue = big.NewInt(1)
					block.Blinded = true
				}

				return block, nil
			},
			populateBlockFunc: func(block *eth2api.VersionedProposal) *eth2api.VersionedSignedBlindedProposal {
				return &eth2api.VersionedSignedBlindedProposal{
					Version: eth2spec.DataVersionElectra,
					Electra: &eth2electra.SignedBlindedBeaconBlock{
						Message:   block.ElectraBlinded,
						Signature: testutil.RandomEth2Signature(),
					},
				}
			},
			createVersionedSignedProposal: func(block *eth2api.VersionedProposal) *eth2api.VersionedSignedProposal {
				signed := testutil.RandomElectraVersionedSignedProposal()
				signed.Electra.SignedBlock.Message = block.Electra.Block

				return signed
			},
		},
		{
			version:              eth2spec.DataVersionDeneb,
			versionedSignedBlock: testutil.RandomDenebVersionedSignedBeaconBlock(),
			beaconMockProposalFunc: func(_ context.Context, opts *eth2api.ProposalOpts) (*eth2api.VersionedProposal, error) {
				var block *eth2api.VersionedProposal
				if opts.BuilderBoostFactor == nil || *opts.BuilderBoostFactor == 0 {
					block = testutil.RandomDenebVersionedProposal()
					block.Deneb.Block.Slot = opts.Slot
					block.Deneb.Block.Body.RANDAOReveal = opts.RandaoReveal
					block.Deneb.Block.Body.Graffiti = opts.Graffiti
					block.ExecutionValue = big.NewInt(1)
					block.ConsensusValue = big.NewInt(1)
				} else {
					block = &eth2api.VersionedProposal{
						Version:      eth2spec.DataVersionDeneb,
						DenebBlinded: testutil.RandomDenebBlindedBeaconBlock(),
					}
					block.DenebBlinded.Slot = opts.Slot
					block.DenebBlinded.Body.RANDAOReveal = opts.RandaoReveal
					block.DenebBlinded.Body.Graffiti = opts.Graffiti
					block.ExecutionValue = big.NewInt(1)
					block.ConsensusValue = big.NewInt(1)
					block.Blinded = true
				}

				return block, nil
			},
			populateBlockFunc: func(block *eth2api.VersionedProposal) *eth2api.VersionedSignedBlindedProposal {
				return &eth2api.VersionedSignedBlindedProposal{
					Version: eth2spec.DataVersionDeneb,
					Deneb: &eth2deneb.SignedBlindedBeaconBlock{
						Message:   block.DenebBlinded,
						Signature: testutil.RandomEth2Signature(),
					},
				}
			},
			createVersionedSignedProposal: func(block *eth2api.VersionedProposal) *eth2api.VersionedSignedProposal {
				signed := testutil.RandomDenebVersionedSignedProposal()
				signed.Deneb.SignedBlock.Message = block.Deneb.Block

				return signed
			},
		},
		{
			version:              eth2spec.DataVersionCapella,
			versionedSignedBlock: testutil.RandomCapellaVersionedSignedBeaconBlock(),
			beaconMockProposalFunc: func(_ context.Context, opts *eth2api.ProposalOpts) (*eth2api.VersionedProposal, error) {
				var block *eth2api.VersionedProposal
				if opts.BuilderBoostFactor == nil || *opts.BuilderBoostFactor == 0 {
					block = testutil.RandomCapellaVersionedProposal()
					block.Capella.Slot = opts.Slot
					block.Capella.Body.RANDAOReveal = opts.RandaoReveal
					block.Capella.Body.Graffiti = opts.Graffiti
					block.ExecutionValue = big.NewInt(1)
					block.ConsensusValue = big.NewInt(1)
				} else {
					block = &eth2api.VersionedProposal{
						Version:        eth2spec.DataVersionCapella,
						CapellaBlinded: testutil.RandomCapellaBlindedBeaconBlock(),
					}
					block.CapellaBlinded.Slot = opts.Slot
					block.CapellaBlinded.Body.RANDAOReveal = opts.RandaoReveal
					block.CapellaBlinded.Body.Graffiti = opts.Graffiti
					block.ExecutionValue = big.NewInt(1)
					block.ConsensusValue = big.NewInt(1)
					block.Blinded = true
				}

				return block, nil
			},
			populateBlockFunc: func(block *eth2api.VersionedProposal) *eth2api.VersionedSignedBlindedProposal {
				return &eth2api.VersionedSignedBlindedProposal{
					Version: eth2spec.DataVersionCapella,
					Capella: &eth2capella.SignedBlindedBeaconBlock{
						Message:   block.CapellaBlinded,
						Signature: testutil.RandomEth2Signature(),
					},
				}
			},
			createVersionedSignedProposal: func(block *eth2api.VersionedProposal) *eth2api.VersionedSignedProposal {
				signed := testutil.RandomCapellaVersionedSignedProposal()
				signed.Capella.Message = block.Capella

				return signed
			},
		},
	}

	for _, test := range tests {
		t.Run(test.version.String(), func(t *testing.T) {
			var (
				set                        = beaconmock.ValidatorSetA
				feeRecipient               = bellatrix.ExecutionAddress{0x00, 0x01, 0x02}
				slotsPerEpoch              = 16
				epoch         eth2p0.Epoch = 100
				realBlockSlot              = eth2p0.Slot(slotsPerEpoch) * eth2p0.Slot(epoch)
				done                       = make(chan struct{})
				activeVals                 = 0
			)

			bmock, err := beaconmock.New(t.Context(), beaconmock.WithValidatorSet(set), beaconmock.WithSlotsPerEpoch(slotsPerEpoch))
			require.NoError(t, err)

			bmock.SubmitProposalFunc = func(ctx context.Context, opts *eth2api.SubmitProposalOpts) error {
				slot, err := opts.Proposal.Slot()
				require.NoError(t, err)
				require.Equal(t, realBlockSlot, slot)
				close(done)

				return nil
			}

			bmock.SubmitBlindedProposalFunc = func(ctx context.Context, opts *eth2api.SubmitBlindedProposalOpts) error {
				slot, err := opts.Proposal.Slot()
				require.NoError(t, err)
				require.Equal(t, realBlockSlot, slot)
				close(done)

				return nil
			}

			bmock.ProposerDutiesFunc = func(ctx context.Context, e eth2p0.Epoch, indices []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
				require.Equal(t, int(epoch), int(e))

				return []*eth2v1.ProposerDuty{ // First validator is the proposer for first slot in the epoch.
					{
						PubKey:         set[1].Validator.PublicKey,
						Slot:           realBlockSlot,
						ValidatorIndex: set[1].Index,
					},
				}, nil
			}
			cached := bmock.CachedValidatorsFunc
			bmock.CachedValidatorsFunc = func(ctx context.Context) (eth2wrap.ActiveValidators, eth2wrap.CompleteValidators, error) {
				activeVals++
				return cached(ctx)
			}
			bmock.SignedBeaconBlockFunc = func(ctx context.Context, blockID string) (*eth2spec.VersionedSignedBeaconBlock, error) {
				resp := test.versionedSignedBlock

				return resp, nil
			}

			bmock.ProposalFunc = test.beaconMockProposalFunc

			eth2Cl := eth2wrap.WithSyntheticDuties(bmock)

			var preps []*eth2v1.ProposalPreparation
			for vIdx := range set {
				preps = append(preps, &eth2v1.ProposalPreparation{
					ValidatorIndex: vIdx,
					FeeRecipient:   feeRecipient,
				})
			}

			require.NoError(t, eth2Cl.SubmitProposalPreparations(ctx, preps))

			// Get synthetic duties
			opts := &eth2api.ProposerDutiesOpts{
				Epoch:   epoch,
				Indices: nil,
			}
			resp1, err := eth2Cl.ProposerDuties(ctx, opts)
			require.NoError(t, err)

			duties := resp1.Data
			require.Len(t, duties, len(set))
			require.Equal(t, 1, activeVals)

			// Get synthetic duties again
			resp2, err := eth2Cl.ProposerDuties(ctx, opts)
			require.NoError(t, err)

			duties2 := resp2.Data
			require.Equal(t, duties, duties2) // Identical
			require.Equal(t, 1, activeVals)   // Cached

			// Submit blocks
			for _, duty := range duties {
				var (
					bbf   uint64 = 100
					graff [32]byte
				)

				copy(graff[:], "test")
				opts1 := &eth2api.ProposalOpts{
					Slot:               duty.Slot,
					RandaoReveal:       testutil.RandomEth2Signature(),
					Graffiti:           graff,
					BuilderBoostFactor: &bbf,
				}
				resp, err := eth2Cl.Proposal(ctx, opts1)
				require.NoError(t, err)

				block := resp.Data
				graffitiInBlock, err := block.Graffiti()
				require.NoError(t, err)
				feeRecipientInBlock, err := block.FeeRecipient()
				require.NoError(t, err)

				if resp.Data.Blinded {
					if duty.Slot == realBlockSlot {
						require.NotContains(t, string(graffitiInBlock[:]), "DO NOT SUBMIT")
						require.NotEqual(t, feeRecipient, feeRecipientInBlock)
					} else {
						require.Equal(t, feeRecipient, feeRecipientInBlock)
					}

					require.Equal(t, test.version, block.Version)

					signed := test.populateBlockFunc(block)
					err = eth2Cl.SubmitBlindedProposal(ctx, &eth2api.SubmitBlindedProposalOpts{
						Proposal: signed,
					})
					require.NoError(t, err)
				} else {
					if duty.Slot == realBlockSlot {
						require.NotContains(t, string(graffitiInBlock[:]), "DO NOT SUBMIT")
						require.NotEqual(t, feeRecipient, feeRecipientInBlock)
					} else {
						require.Contains(t, string(graffitiInBlock[:]), "DO NOT SUBMIT")
						require.Equal(t, feeRecipient, feeRecipientInBlock)

						continue
					}

					require.Equal(t, test.version, block.Version)

					signed := test.createVersionedSignedProposal(block)
					err = eth2Cl.SubmitProposal(ctx, &eth2api.SubmitProposalOpts{
						Proposal: signed,
					})
				}

				require.NoError(t, err)
			}

			<-done
		})
	}
}

func TestSynthProposerBlockNotFound(t *testing.T) {
	ctx := context.Background()

	var (
		set                        = beaconmock.ValidatorSetA
		feeRecipient               = bellatrix.ExecutionAddress{0x00, 0x01, 0x02}
		slotsPerEpoch              = 3
		epoch         eth2p0.Epoch = 1
		realBlockSlot              = eth2p0.Slot(slotsPerEpoch) * eth2p0.Slot(epoch)
		activeVals                 = 0
		timesCalled   int
	)

	bmock, err := beaconmock.New(t.Context(), beaconmock.WithValidatorSet(set), beaconmock.WithSlotsPerEpoch(slotsPerEpoch))
	require.NoError(t, err)

	bmock.ProposerDutiesFunc = func(ctx context.Context, e eth2p0.Epoch, indices []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
		require.Equal(t, int(epoch), int(e))

		return []*eth2v1.ProposerDuty{ // First validator is the proposer for first slot in the epoch.
			{
				PubKey:         set[1].Validator.PublicKey,
				Slot:           realBlockSlot,
				ValidatorIndex: set[1].Index,
			},
		}, nil
	}
	cached := bmock.CachedValidatorsFunc
	bmock.CachedValidatorsFunc = func(ctx context.Context) (eth2wrap.ActiveValidators, eth2wrap.CompleteValidators, error) {
		activeVals++
		return cached(ctx)
	}

	// Return eth2api Error when SignedBeaconBlock is requested.
	bmock.SignedBeaconBlockFunc = func(ctx context.Context, blockID string) (*eth2spec.VersionedSignedBeaconBlock, error) {
		timesCalled++

		return nil, &eth2api.Error{
			Method:     http.MethodGet,
			Endpoint:   "/eth/v2/beacon/blocks/" + blockID,
			StatusCode: http.StatusNotFound,
			Data:       []byte(fmt.Sprintf(`{"code":404,"message":"NOT_FOUND: beacon block at slot %s","stacktraces":[]}`, blockID)),
		}
	}

	// Wrap beacon mock with multi eth2 client implementation which returns wrapped error.
	eth2Cl, err := eth2wrap.Instrument([]eth2wrap.Client{bmock}, nil)
	require.NoError(t, err)

	eth2Cl = eth2wrap.WithSyntheticDuties(eth2Cl)

	var preps []*eth2v1.ProposalPreparation
	for vIdx := range set {
		preps = append(preps, &eth2v1.ProposalPreparation{
			ValidatorIndex: vIdx,
			FeeRecipient:   feeRecipient,
		})
	}

	require.NoError(t, eth2Cl.SubmitProposalPreparations(ctx, preps))

	// Get synthetic duties
	opts := &eth2api.ProposerDutiesOpts{
		Epoch:   epoch,
		Indices: nil,
	}
	resp1, err := eth2Cl.ProposerDuties(ctx, opts)
	require.NoError(t, err)

	duties := resp1.Data
	require.Len(t, duties, len(set))
	require.Equal(t, 1, activeVals)

	// Submit blocks
	for _, duty := range duties {
		timesCalled = 0

		var graff [32]byte
		copy(graff[:], "test")
		opts1 := &eth2api.ProposalOpts{
			Slot:         duty.Slot,
			RandaoReveal: testutil.RandomEth2Signature(),
			Graffiti:     graff,
		}
		_, err = eth2Cl.Proposal(ctx, opts1)
		require.ErrorContains(t, err, "no proposal found to base synthetic proposal on")

		// SignedBeaconBlock will be called for previous slots starting from duty.Slot-1 upto slot 0 (exclusive).
		require.Equal(t, timesCalled, int(duty.Slot)-1)
	}
}
