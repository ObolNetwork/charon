// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatormock

import (
	"context"

	eth2api "github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/eth2util/signing"
)

// prefsFeeRecipient is the fee recipient all validatormock proposer preferences carry.
// It is a fixed constant since all mock VCs in a cluster must submit identical preferences
// for the partial signatures to aggregate.
var prefsFeeRecipient = bellatrix.ExecutionAddress{0xde, 0xad, 0xbe, 0xef}

// prefsTargetGasLimit is the target gas limit all validatormock proposer preferences carry.
const prefsTargetGasLimit = 30_000_000

// ProposerPreferences submits signed proposer preferences for the provided future proposal
// slot. It is stateless and does nothing if no active validator is the proposer for the slot.
func ProposerPreferences(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc, slot eth2p0.Slot) error {
	valMap, err := eth2Cl.ActiveValidators(ctx)
	if err != nil {
		return err
	}

	_, slotsPerEpoch, err := eth2wrap.FetchSlotsConfig(ctx, eth2Cl)
	if err != nil {
		return err
	}

	epoch := eth2p0.Epoch(uint64(slot) / slotsPerEpoch)

	var indexes []eth2p0.ValidatorIndex
	for index := range valMap {
		indexes = append(indexes, index)
	}

	// The v2 endpoint returns the E-2 shuffling anchor as dependent_root, the root the
	// preferences sign over.
	eth2Resp, err := eth2Cl.ProposerDutiesV2(ctx, &eth2api.ProposerDutiesOpts{
		Epoch:   epoch,
		Indices: indexes,
	})
	if err != nil {
		return err
	}

	var prefs []*gloas.SignedProposerPreferences

	for _, duty := range eth2Resp.Data {
		if duty == nil {
			return errors.New("proposer duty is nil")
		}

		if duty.Slot != slot {
			continue
		}

		msg := &gloas.ProposerPreferences{
			DependentRoot:  dependentRoot(eth2Resp.Metadata),
			ProposalSlot:   duty.Slot,
			ValidatorIndex: duty.ValidatorIndex,
			FeeRecipient:   prefsFeeRecipient,
			TargetGasLimit: prefsTargetGasLimit,
		}

		root, err := msg.HashTreeRoot()
		if err != nil {
			return errors.Wrap(err, "hash proposer preferences")
		}

		sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainProposerPreferences, epoch, root)
		if err != nil {
			return err
		}

		sig, err := signFunc(duty.PubKey, sigData[:])
		if err != nil {
			return err
		}

		prefs = append(prefs, &gloas.SignedProposerPreferences{
			Message:   msg,
			Signature: sig,
		})
	}

	if len(prefs) == 0 {
		return nil
	}

	return eth2Cl.SubmitProposerPreferences(ctx, prefs)
}

// dependentRoot returns the dependent root from the proposer duties response metadata,
// or a zero root if absent.
func dependentRoot(metadata map[string]any) eth2p0.Root {
	root, ok := metadata["dependent_root"].(eth2p0.Root)
	if !ok {
		return eth2p0.Root{}
	}

	return root
}
