// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"context"
	"math/rand"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	"github.com/attestantio/go-eth2-client/spec"
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

	bmock.SubmitBeaconBlockFunc = func(ctx context.Context, block *spec.VersionedSignedBeaconBlock) error {
		require.Equal(t, realBlockSlot, block.Capella.Message.Slot)
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
	cached := bmock.ActiveValidatorsFunc
	bmock.ActiveValidatorsFunc = func(ctx context.Context) (eth2wrap.ActiveValidators, error) {
		activeVals++
		return cached(ctx)
	}
	signedBeaconBlock := bmock.SignedBeaconBlock
	bmock.SignedBeaconBlockFunc = func(ctx context.Context, blockID string) (*spec.VersionedSignedBeaconBlock, error) {
		if rand.Float32() < 0.3 { // Fail to find 2/3 of blocks.
			return nil, nil //nolint:nilnil // go-eth2-client returns nilnil if block not found.
		}

		return signedBeaconBlock(ctx, blockID)
	}

	eth2Cl := eth2wrap.WithSyntheticDuties(bmock, set.PublicKeys())

	var preps []*eth2v1.ProposalPreparation
	for vIdx := range set {
		preps = append(preps, &eth2v1.ProposalPreparation{
			ValidatorIndex: vIdx,
			FeeRecipient:   feeRecipient,
		})
	}
	require.NoError(t, eth2Cl.SubmitProposalPreparations(ctx, preps))

	// Get synthetic duties
	duties, err := eth2Cl.ProposerDuties(ctx, epoch, nil)
	require.NoError(t, err)
	require.Len(t, duties, len(set))
	require.Equal(t, 1, activeVals)

	// Get synthetic duties again
	duties2, err := eth2Cl.ProposerDuties(ctx, epoch, nil)
	require.NoError(t, err)
	require.Equal(t, duties, duties2) // Identical
	require.Equal(t, 1, activeVals)   // Cached

	// Submit blocks
	for _, duty := range duties {
		block, err := eth2Cl.BeaconBlockProposal(ctx, duty.Slot, testutil.RandomEth2Signature(), []byte("test"))
		require.NoError(t, err)
		if duty.Slot == realBlockSlot {
			require.NotContains(t, string(block.Capella.Body.Graffiti[:]), "DO NOT SUBMIT")
			require.NotEqual(t, feeRecipient, block.Capella.Body.ExecutionPayload.FeeRecipient)
		} else {
			require.Contains(t, string(block.Capella.Body.Graffiti[:]), "DO NOT SUBMIT")
			require.Equal(t, feeRecipient, block.Capella.Body.ExecutionPayload.FeeRecipient)
		}
		require.Equal(t, spec.DataVersionCapella, block.Version)

		signed := testutil.RandomCapellaVersionedSignedBeaconBlock()
		signed.Capella.Message = block.Capella
		err = eth2Cl.SubmitBeaconBlock(ctx, signed)
		require.NoError(t, err)
	}

	// Submit blinded blocks
	for _, duty := range duties {
		block, err := eth2Cl.BlindedBeaconBlockProposal(ctx, duty.Slot, testutil.RandomEth2Signature(), []byte("test"))
		require.NoError(t, err)
		if duty.Slot == realBlockSlot {
			require.NotContains(t, string(block.Capella.Body.Graffiti[:]), "DO NOT SUBMIT")
			require.NotEqual(t, feeRecipient, block.Capella.Body.ExecutionPayloadHeader.FeeRecipient)
		} else {
			require.Equal(t, feeRecipient, block.Capella.Body.ExecutionPayloadHeader.FeeRecipient)
		}
		require.Equal(t, spec.DataVersionCapella, block.Version)

		signed := &eth2api.VersionedSignedBlindedBeaconBlock{
			Version: spec.DataVersionCapella,
			Capella: &eth2capella.SignedBlindedBeaconBlock{
				Message:   block.Capella,
				Signature: testutil.RandomEth2Signature(),
			},
		}
		err = eth2Cl.SubmitBlindedBeaconBlock(ctx, signed)
		require.NoError(t, err)
	}

	<-done
}
