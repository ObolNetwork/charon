// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package bcast provides the core workflow's broadcaster component that
// broadcasts/submits aggregated signed duty data to the beacon node.
package bcast

import (
	"context"
	"strings"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
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
	delayFunc func(slot uint64) time.Duration
}

// Broadcast broadcasts the aggregated signed duty data object to the beacon-node.
func (b Broadcaster) Broadcast(ctx context.Context, duty core.Duty, set core.SignedDataSet) (err error) {
	ctx = log.WithTopic(ctx, "bcast")
	defer func() {
		if err == nil {
			instrumentDuty(duty, b.delayFunc(duty.Slot))
		}
	}()

	switch duty.Type {
	case core.DutyAttester:
		isElectra, err := isElectraAttestation(set)
		if err != nil {
			return err
		}

		if isElectra {
			atts, err := setToAttestationsV2(set)
			if err != nil {
				return err
			}

			err = b.eth2Cl.SubmitAttestationsV2(ctx, &eth2api.SubmitAttestationsOpts{Attestations: atts})
			if err != nil && strings.Contains(err.Error(), "PriorAttestationKnown") {
				// Lighthouse isn't idempotent, so just swallow this non-issue.
				// See reference github.com/attestantio/go-eth2-client@v0.11.7/multi/submitattestations.go:38
				err = nil
			}
			if err == nil {
				log.Info(ctx, "Successfully submitted v2 attestations to beacon node",
					z.Any("delay", b.delayFunc(duty.Slot)),
				)
			}
		} else {
			atts, err := setToAttestations(set)
			if err != nil {
				return err
			}

			err = b.eth2Cl.SubmitAttestations(ctx, atts)
			if err != nil && strings.Contains(err.Error(), "PriorAttestationKnown") {
				// Lighthouse isn't idempotent, so just swallow this non-issue.
				// See reference github.com/attestantio/go-eth2-client@v0.11.7/multi/submitattestations.go:38
				err = nil
			}
			if err == nil {
				log.Info(ctx, "Successfully submitted v1 attestations to beacon node",
					z.Any("delay", b.delayFunc(duty.Slot)),
				)
			}
		}

		return err

	case core.DutyProposer:
		pubkey, aggData, err := setToOne(set)
		if err != nil {
			return err
		}

		var (
			block core.VersionedSignedProposal
			ok    bool
		)

		block, ok = aggData.(core.VersionedSignedProposal)
		if !ok {
			return errors.New("invalid proposal")
		}

		switch block.Blinded {
		case true:
			var blinded eth2api.VersionedSignedBlindedProposal

			blinded, err = block.ToBlinded()
			if err != nil {
				return errors.Wrap(err, "cannot broadcast, expected blinded proposal")
			}

			err = b.eth2Cl.SubmitBlindedProposal(ctx, &eth2api.SubmitBlindedProposalOpts{
				Proposal: &blinded,
			})
		default:
			err = b.eth2Cl.SubmitProposal(ctx, &eth2api.SubmitProposalOpts{
				Proposal: &block.VersionedSignedProposal,
			})
		}

		if err == nil {
			log.Info(ctx, "Successfully submitted block proposal to beacon node",
				z.Any("delay", b.delayFunc(duty.Slot)),
				z.Any("pubkey", pubkey),
				z.Bool("blinded", block.Blinded),
			)
		}

		return err

	case core.DutyBuilderProposer:
		return core.ErrDeprecatedDutyBuilderProposer

	case core.DutyBuilderRegistration:
		slot, err := firstSlotInCurrentEpoch(ctx, b.eth2Cl)
		if err != nil {
			return errors.Wrap(err, "calculate first slot in epoch")
		}

		// Use first slot in current epoch for accurate delay calculations while submitting builder registrations.
		// This is because builder registrations are submitted in first slot of every epoch.
		duty.Slot = slot
		registrations, err := setToRegistrations(set)
		if err != nil {
			return err
		}

		err = b.eth2Cl.SubmitValidatorRegistrations(ctx, registrations)
		if err == nil {
			log.Info(ctx, "Successfully submitted validator registrations to beacon node",
				z.Any("delay", b.delayFunc(duty.Slot)),
			)
		}

		return err

	case core.DutyExit:
		var err error // Try submitting all exits and return last error.
		for pubkey, aggData := range set {
			exit, ok := aggData.(core.SignedVoluntaryExit)
			if !ok {
				return errors.New("invalid exit")
			}

			err = b.eth2Cl.SubmitVoluntaryExit(ctx, &exit.SignedVoluntaryExit)
			if err == nil {
				log.Info(ctx, "Successfully submitted voluntary exit to beacon node",
					z.Any("delay", b.delayFunc(duty.Slot)),
					z.Any("pubkey", pubkey),
				)
			}
		}

		return err
	case core.DutyRandao:
		// Randao is an internal duty, not broadcasted to beacon chain.
		return nil
	case core.DutyPrepareAggregator:
		// Beacon committee selections are only applicable to DVT, not broadcasted to beacon chain.
		return nil
	case core.DutyAggregator:
		isElectra, err := isElectraAggAndProof(set)
		if err != nil {
			return err
		}

		if isElectra {
			aggAndProofs, err := setToAggAndProofV2(set)
			if err != nil {
				return err
			}

			err = b.eth2Cl.SubmitAggregateAttestationsV2(ctx, aggAndProofs)
			if err == nil {
				log.Info(ctx, "Successfully submitted v2 attestation aggregations to beacon node",
					z.Any("delay", b.delayFunc(duty.Slot)))
			}
		} else {
			aggAndProofs, err := setToAggAndProof(set)
			if err != nil {
				return err
			}

			err = b.eth2Cl.SubmitAggregateAttestations(ctx, aggAndProofs)
			if err == nil {
				log.Info(ctx, "Successfully submitted v1 attestation aggregations to beacon node",
					z.Any("delay", b.delayFunc(duty.Slot)))
			}
		}

		return err
	case core.DutySyncMessage:
		msgs, err := setToSyncMessages(set)
		if err != nil {
			return err
		}

		err = b.eth2Cl.SubmitSyncCommitteeMessages(ctx, msgs)
		if err == nil {
			log.Info(ctx, "Successfully submitted sync committee messages to beacon node",
				z.Any("delay", b.delayFunc(duty.Slot)))
		}

		return err
	case core.DutyPrepareSyncContribution:
		// Sync committee selections are only applicable to DVT, not broadcasted to beacon chain.
		return nil
	case core.DutySyncContribution:
		contributions, err := setToSyncContributions(set)
		if err != nil {
			return err
		}

		err = b.eth2Cl.SubmitSyncCommitteeContributions(ctx, contributions)
		if err == nil {
			log.Info(ctx, "Successfully submitted sync committee contributions to beacon node",
				z.Any("delay", b.delayFunc(duty.Slot)))
		}

		return err
	default:
		return errors.New("unsupported duty type")
	}
}

// setToSyncContributions converts a set of signed data into a list of sync committee contributions.
func setToSyncContributions(set core.SignedDataSet) ([]*altair.SignedContributionAndProof, error) {
	var resp []*altair.SignedContributionAndProof
	for _, contribution := range set {
		contribution, ok := contribution.(core.SignedSyncContributionAndProof)
		if !ok {
			return nil, errors.New("invalid sync committee contribution")
		}

		resp = append(resp, &contribution.SignedContributionAndProof)
	}

	return resp, nil
}

// setToSyncMessages converts a set of signed data into a list of sync committee messages.
func setToSyncMessages(set core.SignedDataSet) ([]*altair.SyncCommitteeMessage, error) {
	var resp []*altair.SyncCommitteeMessage
	for _, msg := range set {
		msg, ok := msg.(core.SignedSyncMessage)
		if !ok {
			return nil, errors.New("invalid sync committee message")
		}

		resp = append(resp, &msg.SyncCommitteeMessage)
	}

	return resp, nil
}

// isElectraAggAndProof checks if a core.SignedDataSet object is pre- or post-electra aggregate and proof.
func isElectraAggAndProof(set core.SignedDataSet) (bool, error) {
	for _, att := range set {
		_, ok := att.(core.SignedAggregateAndProof)
		if ok {
			return false, nil
		}

		_, ok = att.(core.VersionedSignedAggregateAndProof)
		if ok {
			return true, nil
		}

		return false, errors.New("invalid aggregate and proof")
	}

	return false, errors.New("empty aggregates and proof signed data set")
}

// setToAggAndProof converts a set of signed data into a list of aggregate and proofs.
func setToAggAndProof(set core.SignedDataSet) ([]*eth2p0.SignedAggregateAndProof, error) {
	var resp []*eth2p0.SignedAggregateAndProof
	for _, aggAndProof := range set {
		aggAndProof, ok := aggAndProof.(core.SignedAggregateAndProof)
		if !ok {
			return nil, errors.New("invalid aggregate and proof")
		}

		resp = append(resp, &aggAndProof.SignedAggregateAndProof)
	}

	return resp, nil
}

// setToAggAndProofV2 converts a set of signed data into a list of versioned aggregate and proofs.
func setToAggAndProofV2(set core.SignedDataSet) (*eth2api.SubmitAggregateAttestationsOpts, error) {
	var resp []*eth2spec.VersionedSignedAggregateAndProof
	for _, aggAndProof := range set {
		aggAndProof, ok := aggAndProof.(core.VersionedSignedAggregateAndProof)
		if !ok {
			return nil, errors.New("invalid aggregate and proof")
		}

		resp = append(resp, &aggAndProof.VersionedSignedAggregateAndProof)
	}

	return &eth2api.SubmitAggregateAttestationsOpts{SignedAggregateAndProofs: resp}, nil
}

// setToRegistrations converts a set of signed data into a list of registrations.
func setToRegistrations(set core.SignedDataSet) ([]*eth2api.VersionedSignedValidatorRegistration, error) {
	var resp []*eth2api.VersionedSignedValidatorRegistration
	for _, reg := range set {
		reg, ok := reg.(core.VersionedSignedValidatorRegistration)
		if !ok {
			return nil, errors.New("invalid registration")
		}

		resp = append(resp, &reg.VersionedSignedValidatorRegistration)
	}

	return resp, nil
}

// setToOne converts a set of signed data into a single signed data.
func setToOne(set core.SignedDataSet) (core.PubKey, core.SignedData, error) {
	if len(set) != 1 {
		return "", nil, errors.New("expected one item in set")
	}

	for pubkey, data := range set {
		return pubkey, data, nil
	}

	return "", nil, errors.New("expected one item in set")
}

// isElectraAttestation checks if a core.SignedDataSet object is pre- or post-electra attestation.
func isElectraAttestation(set core.SignedDataSet) (bool, error) {
	for _, att := range set {
		_, ok := att.(core.Attestation)
		if ok {
			return false, nil
		}

		_, ok = att.(core.VersionedAttestation)
		if ok {
			return true, nil
		}

		return false, errors.New("invalid attestation")
	}

	return false, errors.New("empty attestations signed data set")
}

// setToAttestations converts a set of signed data into a list of attestations.
func setToAttestations(set core.SignedDataSet) ([]*eth2p0.Attestation, error) {
	var resp []*eth2p0.Attestation
	for _, att := range set {
		att, ok := att.(core.Attestation)
		if !ok {
			return nil, errors.New("invalid attestation")
		}
		resp = append(resp, &att.Attestation)
	}

	return resp, nil
}

// setToAttestationsV2 converts a set of signed data into a list of versioned attestations.
func setToAttestationsV2(set core.SignedDataSet) ([]*eth2spec.VersionedAttestation, error) {
	var resp []*eth2spec.VersionedAttestation
	for _, att := range set {
		att, ok := att.(core.VersionedAttestation)
		if !ok {
			return nil, errors.New("invalid attestation")
		}
		resp = append(resp, &att.VersionedAttestation)
	}

	return resp, nil
}

// newDelayFunc returns a function that calculates the delay since the start of a slot.
func newDelayFunc(ctx context.Context, eth2Cl eth2wrap.Client) (func(slot uint64) time.Duration, error) {
	genesis, err := eth2Cl.GenesisTime(ctx)
	if err != nil {
		return nil, err
	}

	eth2Resp, err := eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
	if err != nil {
		return nil, err
	}

	slotDuration, ok := eth2Resp.Data["SECONDS_PER_SLOT"].(time.Duration)
	if !ok {
		return nil, errors.New("fetch slot duration")
	}

	return func(slot uint64) time.Duration {
		slotStart := genesis.Add(slotDuration * time.Duration(slot))
		return time.Since(slotStart)
	}, nil
}

// firstSlotInCurrentEpoch calculates first slot number of the current ongoing epoch.
func firstSlotInCurrentEpoch(ctx context.Context, eth2Cl eth2wrap.Client) (uint64, error) {
	genesis, err := eth2Cl.Genesis(ctx, &eth2api.GenesisOpts{})
	if err != nil {
		return 0, errors.Wrap(err, "fetch genesis")
	}

	eth2Resp, err := eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
	if err != nil {
		return 0, err
	}
	spec := eth2Resp.Data

	slotDuration, ok := spec["SECONDS_PER_SLOT"].(time.Duration)
	if !ok {
		return 0, errors.New("fetch slot duration")
	}

	slotsPerEpoch, ok := spec["SLOTS_PER_EPOCH"].(uint64)
	if !ok {
		return 0, errors.New("fetch slots per epoch")
	}

	chainAge := time.Since(genesis.Data.GenesisTime)
	currentSlot := chainAge / slotDuration
	currentEpoch := uint64(currentSlot) / slotsPerEpoch

	return currentEpoch * slotsPerEpoch, nil
}
