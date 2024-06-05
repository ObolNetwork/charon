// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
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

	var (
		set                        = beaconmock.ValidatorSetA
		feeRecipient               = bellatrix.ExecutionAddress{0x00, 0x01, 0x02}
		slotsPerEpoch              = 16
		epoch         eth2p0.Epoch = 100
		realBlockSlot              = eth2p0.Slot(slotsPerEpoch) * eth2p0.Slot(epoch)
		done                       = make(chan struct{})
		activeVals                 = 0
	)

	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(set), beaconmock.WithSlotsPerEpoch(slotsPerEpoch))
	require.NoError(t, err)

	bmock.SubmitProposalFunc = func(ctx context.Context, opts *eth2api.SubmitProposalOpts) error {
		require.Equal(t, realBlockSlot, opts.Proposal.Capella.Message.Slot)
		close(done)

		return nil
	}

	bmock.SubmitBlindedProposalFunc = func(ctx context.Context, opts *eth2api.SubmitBlindedProposalOpts) error {
		require.Equal(t, realBlockSlot, opts.Proposal.Capella.Message.Slot)
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
	signedBeaconBlock := bmock.SignedBeaconBlock
	bmock.SignedBeaconBlockFunc = func(ctx context.Context, blockID string) (*eth2spec.VersionedSignedBeaconBlock, error) {
		opts := &eth2api.SignedBeaconBlockOpts{Block: blockID}
		resp, err := signedBeaconBlock(ctx, opts)
		if err != nil {
			return nil, err
		}

		return resp.Data, nil
	}

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
		var bbf uint64 = 100
		var graff [32]byte
		copy(graff[:], "test")
		opts1 := &eth2api.ProposalOpts{
			Slot:               duty.Slot,
			RandaoReveal:       testutil.RandomEth2Signature(),
			Graffiti:           graff,
			BuilderBoostFactor: &bbf,
		}
		resp, err := eth2Cl.Proposal(ctx, opts1)
		require.NoError(t, err)

		if resp.Data.Blinded {
			block := resp.Data
			if duty.Slot == realBlockSlot {
				require.NotContains(t, string(block.CapellaBlinded.Body.Graffiti[:]), "DO NOT SUBMIT")
				require.NotEqual(t, feeRecipient, block.CapellaBlinded.Body.ExecutionPayloadHeader.FeeRecipient)
			} else {
				require.Equal(t, feeRecipient, block.CapellaBlinded.Body.ExecutionPayloadHeader.FeeRecipient)
			}
			require.Equal(t, eth2spec.DataVersionCapella, block.Version)

			signed := &eth2api.VersionedSignedBlindedProposal{
				Version: eth2spec.DataVersionCapella,
				Capella: &eth2capella.SignedBlindedBeaconBlock{
					Message:   block.CapellaBlinded,
					Signature: testutil.RandomEth2Signature(),
				},
			}
			err = eth2Cl.SubmitBlindedProposal(ctx, &eth2api.SubmitBlindedProposalOpts{
				Proposal: signed,
			})
			require.NoError(t, err)
		} else {
			block := resp.Data

			if duty.Slot == realBlockSlot {
				require.NotContains(t, string(block.Capella.Body.Graffiti[:]), "DO NOT SUBMIT")
				require.NotEqual(t, feeRecipient, block.Capella.Body.ExecutionPayload.FeeRecipient)
			} else {
				require.Contains(t, string(block.Capella.Body.Graffiti[:]), "DO NOT SUBMIT")
				require.Equal(t, feeRecipient, block.Capella.Body.ExecutionPayload.FeeRecipient)

				continue
			}
			require.Equal(t, eth2spec.DataVersionCapella, block.Version)

			signed := testutil.RandomCapellaVersionedSignedProposal()
			signed.Capella.Message = block.Capella
			err = eth2Cl.SubmitProposal(ctx, &eth2api.SubmitProposalOpts{
				Proposal: signed,
			})
		}
		require.NoError(t, err)
	}

	<-done
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

	bmock, err := beaconmock.New(beaconmock.WithValidatorSet(set), beaconmock.WithSlotsPerEpoch(slotsPerEpoch))
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
			Endpoint:   fmt.Sprintf("/eth/v2/beacon/blocks/%s", blockID),
			StatusCode: http.StatusNotFound,
			Data:       []byte(fmt.Sprintf(`{"code":404,"message":"NOT_FOUND: beacon block at slot %s","stacktraces":[]}`, blockID)),
		}
	}

	// Wrap beacon mock with multi eth2 client implementation which returns wrapped error.
	eth2Cl, err := eth2wrap.Instrument(bmock)
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
