// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package bcast provides the core workflow's broadcaster component that
// broadcasts/submits aggregated signed duty data to the beacon node.
package bcast

import (
	"context"
	"strings"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

// New returns a new broadcaster instance.
func New(ctx context.Context, eth2Cl eth2wrap.Client) (Broadcaster, error) {
	delayFunc, err := newDelayFunc(ctx, eth2Cl)
	if err != nil {
		return Broadcaster{}, err
	}

	return Broadcaster{
		eth2Cl:    eth2Cl,
		delayFunc: delayFunc,
	}, nil
}

type Broadcaster struct {
	eth2Cl    eth2wrap.Client
	delayFunc func(slot int64) time.Duration
}

// Broadcast broadcasts the aggregated signed duty data object to the beacon-node.
func (b Broadcaster) Broadcast(ctx context.Context, duty core.Duty, pubkey core.PubKey, aggData core.SignedData) (err error) {
	ctx = log.WithTopic(ctx, "bcast")
	ctx = log.WithCtx(ctx, z.Any("pubkey", pubkey))
	defer func() {
		if err == nil {
			instrumentDuty(duty, b.delayFunc(duty.Slot))
		}
	}()

	switch duty.Type {
	case core.DutyAttester:
		att, ok := aggData.(core.Attestation)
		if !ok {
			return errors.New("invalid attestation")
		}

		err = b.eth2Cl.SubmitAttestations(ctx, []*eth2p0.Attestation{&att.Attestation})
		if err != nil && strings.Contains(err.Error(), "PriorAttestationKnown") {
			// Lighthouse isn't idempotent, so just swallow this non-issue.
			// See reference github.com/attestantio/go-eth2-client@v0.11.7/multi/submitattestations.go:38
			err = nil
		}
		if err == nil {
			log.Info(ctx, "Successfully submitted attestation to beacon node",
				z.Any("delay", b.delayFunc(duty.Slot)),
			)
		}

		return err
	case core.DutyProposer:
		block, ok := aggData.(core.VersionedSignedBeaconBlock)
		if !ok {
			return errors.New("invalid block")
		}

		err = b.eth2Cl.SubmitBeaconBlock(ctx, &block.VersionedSignedBeaconBlock)
		if err == nil {
			log.Info(ctx, "Successfully submitted block proposal to beacon node",
				z.Any("delay", b.delayFunc(duty.Slot)),
			)
		}

		return err

	case core.DutyBuilderProposer:
		block, ok := aggData.(core.VersionedSignedBlindedBeaconBlock)
		if !ok {
			return errors.New("invalid block")
		}

		err = b.eth2Cl.SubmitBlindedBeaconBlock(ctx, &block.VersionedSignedBlindedBeaconBlock)
		if err == nil {
			log.Info(ctx, "Successfully submitted blinded block proposal to beacon node",
				z.Any("delay", b.delayFunc(duty.Slot)),
			)
		}

		return err

	case core.DutyBuilderRegistration:
		registration, ok := aggData.(core.VersionedSignedValidatorRegistration)
		if !ok {
			return errors.New("invalid validator registration")
		}

		err = b.eth2Cl.SubmitValidatorRegistrations(ctx, []*eth2api.VersionedSignedValidatorRegistration{&registration.VersionedSignedValidatorRegistration})
		if err == nil {
			log.Info(ctx, "Successfully submitted validator registration to beacon node",
				z.Any("delay", b.delayFunc(duty.Slot)),
			)
			registrationSlotGauge.WithLabelValues(pubkey.String()).Set(float64(duty.Slot))
		}

		return err

	case core.DutyExit:
		exit, ok := aggData.(core.SignedVoluntaryExit)
		if !ok {
			return errors.New("invalid exit")
		}

		err = b.eth2Cl.SubmitVoluntaryExit(ctx, &exit.SignedVoluntaryExit)
		if err == nil {
			log.Info(ctx, "Successfully submitted voluntary exit to beacon node",
				z.Any("delay", b.delayFunc(duty.Slot)),
			)
		}

		return err
	case core.DutyRandao:
		// Randao is an internal duty, not broadcasted to beacon chain.
		return nil
	case core.DutyPrepareAggregator:
		// Beacon committee selections are only applicable to DVT, not broadcasted to beacon chain.
		return nil
	case core.DutyAggregator:
		aggAndProof, ok := aggData.(core.SignedAggregateAndProof)
		if !ok {
			return errors.New("invalid aggregate and proof")
		}

		err = b.eth2Cl.SubmitAggregateAttestations(ctx, []*eth2p0.SignedAggregateAndProof{&aggAndProof.SignedAggregateAndProof})
		if err == nil {
			log.Info(ctx, "Successfully submitted attestation aggregation to beacon node",
				z.Any("delay", b.delayFunc(duty.Slot)))
		}

		return err
	case core.DutySyncMessage:
		msg, ok := aggData.(core.SignedSyncMessage)
		if !ok {
			return errors.New("invalid sync committee message")
		}

		err := b.eth2Cl.SubmitSyncCommitteeMessages(ctx, []*altair.SyncCommitteeMessage{&msg.SyncCommitteeMessage})
		if err == nil {
			log.Info(ctx, "Successfully submitted sync committee message to beacon node",
				z.Any("delay", b.delayFunc(duty.Slot)))
		}

		return err
	case core.DutyPrepareSyncContribution:
		// Sync committee selections are only applicable to DVT, not broadcasted to beacon chain.
		return nil
	case core.DutySyncContribution:
		contribution, ok := aggData.(core.SignedSyncContributionAndProof)
		if !ok {
			return errors.New("invalid sync contribution and proof")
		}

		err := b.eth2Cl.SubmitSyncCommitteeContributions(ctx, []*altair.SignedContributionAndProof{&contribution.SignedContributionAndProof})
		if err == nil {
			log.Info(ctx, "Successfully submitted sync committee contribution to beacon node",
				z.Any("delay", b.delayFunc(duty.Slot)))
		}

		return err
	default:
		return errors.New("unsupported duty type")
	}
}

// newDelayFunc returns a function that calculates the delay since the start of a slot.
func newDelayFunc(ctx context.Context, eth2Cl eth2wrap.Client) (func(slot int64) time.Duration, error) {
	genesis, err := eth2Cl.GenesisTime(ctx)
	if err != nil {
		return nil, err
	}

	slotDuration, err := eth2Cl.SlotDuration(ctx)
	if err != nil {
		return nil, err
	}

	return func(slot int64) time.Duration {
		slotStart := genesis.Add(slotDuration * time.Duration(slot))
		return time.Since(slotStart)
	}, nil
}
