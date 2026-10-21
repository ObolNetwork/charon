// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatormock

import (
	"context"

	eth2api "github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/signing"
)

// builderPrefsMaxExecutionPayment is the maximum execution payment the mock submits with each
// builder preferences entry. Charon submits its own configured value instead.
const builderPrefsMaxExecutionPayment eth2p0.Gwei = 1_000_000_000

// BuilderPreferences submits the builder preferences of the provided future proposal slot: a
// builder request auth for each builder URL. It is stateless and does nothing if no active
// validator is the proposer for the slot or no builders are configured.
func BuilderPreferences(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc, slot eth2p0.Slot, builderURLs []string) error {
	if len(builderURLs) == 0 {
		return nil
	}

	valMap, err := eth2Cl.ActiveValidators(ctx)
	if err != nil {
		return err
	}

	_, slotsPerEpoch, err := eth2wrap.FetchSlotsConfig(ctx, eth2Cl)
	if err != nil {
		return err
	}

	epoch := eth2p0.Epoch(uint64(slot) / slotsPerEpoch)

	forkSchedule, err := eth2wrap.FetchForkConfig(ctx, eth2Cl)
	if err != nil {
		return err
	}

	// Preferences only exist from the gloas fork onwards.
	if !forkSchedule.Active(eth2wrap.Gloas, epoch) {
		return nil
	}

	var indexes []eth2p0.ValidatorIndex
	for index := range valMap {
		indexes = append(indexes, index)
	}

	eth2Resp, err := eth2Cl.ProposerDutiesV2(ctx, &eth2api.ProposerDutiesOpts{
		Epoch:   epoch,
		Indices: indexes,
	})
	if err != nil {
		return err
	}

	var entries []*gloas.BuilderPreferencesEntry

	for _, duty := range eth2Resp.Data {
		if duty == nil {
			return errors.New("proposer duty is nil")
		}

		if duty.Slot != slot {
			continue
		}

		for _, url := range builderURLs {
			data, err := eth2util.BuilderAuthData(url)
			if err != nil {
				return err
			}

			msg := &gloas.BuilderRequestAuth{Data: data, Slot: slot}

			root, err := msg.HashTreeRoot()
			if err != nil {
				return errors.Wrap(err, "hash builder request auth")
			}

			sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainBuilderRequestAuth, epoch, root)
			if err != nil {
				return err
			}

			sig, err := signFunc(duty.PubKey, sigData[:])
			if err != nil {
				return err
			}

			entries = append(entries, &gloas.BuilderPreferencesEntry{
				ProposerPubkey:      duty.PubKey,
				URL:                 []byte(url),
				Auth:                &gloas.SignedBuilderRequestAuth{Message: msg, Signature: sig},
				MaxExecutionPayment: builderPrefsMaxExecutionPayment,
			})
		}
	}

	if len(entries) == 0 {
		return nil
	}

	return eth2Cl.SubmitBuilderPreferences(ctx, &eth2api.SubmitBuilderPreferencesOpts{Preferences: entries})
}
