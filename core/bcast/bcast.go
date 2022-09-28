// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

// Package bcast provides the core workflow's broadcaster component that
// broadcasts/submits aggregated signed duty data to the beacon node.
package bcast

import (
	"context"
	"strings"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
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
func (b Broadcaster) Broadcast(ctx context.Context, duty core.Duty, pubkey core.PubKey, aggData core.SignedData) (err error) { //nolint:gocognit
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
		// Randao is an internal duty, not broadcasted to beacon chain
		return nil
	case core.DutyPrepareAggregator:
		sub, ok := aggData.(core.SignedBeaconCommitteeSubscription)
		if !ok {
			return errors.New("invalid beacon committee sub")
		}

		_, err = b.eth2Cl.SubmitBeaconCommitteeSubscriptionsV2(ctx, []*eth2exp.BeaconCommitteeSubscription{&sub.BeaconCommitteeSubscription})
		if err == nil {
			return nil
		}

		// Ignore error as beacon node probably doesn't support v2 SubmitBeaconCommitteeSubscriptions
		// endpoint (yet). Just try again with v1.

		res, err := eth2exp.CalculateCommitteeSubscriptionResponse(ctx, b.eth2Cl, &sub.BeaconCommitteeSubscription)
		if err != nil {
			return err
		}

		subs := []*eth2v1.BeaconCommitteeSubscription{{
			ValidatorIndex:   res.ValidatorIndex,
			Slot:             res.Slot,
			CommitteeIndex:   res.CommitteeIndex,
			CommitteesAtSlot: res.CommitteesAtSlot,
			IsAggregator:     res.IsAggregator,
		}}

		err = b.eth2Cl.SubmitBeaconCommitteeSubscriptions(ctx, subs)
		if err == nil {
			log.Info(ctx, "Successfully submitted beacon committee subscription to beacon node",
				z.Any("delay", b.delayFunc(duty.Slot)))
		}

		return err
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
