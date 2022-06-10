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
// broadcasts/submits aggregated singed duty data to the beacon-node.
package bcast

import (
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

type eth2Provider interface {
	eth2client.AttestationsSubmitter
	eth2client.BeaconBlockSubmitter
	eth2client.VoluntaryExitSubmitter
	eth2client.GenesisTimeProvider
	eth2client.SlotDurationProvider
}

// New returns a new broadcaster instance.
func New(ctx context.Context, eth2Svc eth2client.Service) (Broadcaster, error) {
	eth2Cl, ok := eth2Svc.(eth2Provider)
	if !ok {
		return Broadcaster{}, errors.New("invalid eth2 service")
	}

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
	eth2Cl    eth2Provider
	delayFunc func(slot int64) time.Duration
}

// Broadcast broadcasts the aggregated signed duty data object to the beacon-node.
func (b Broadcaster) Broadcast(ctx context.Context, duty core.Duty,
	pubkey core.PubKey, aggData core.AggSignedData,
) (err error) {
	ctx = log.WithTopic(ctx, "bcast")
	defer func() {
		if err == nil {
			instrumentDuty(duty, pubkey, b.delayFunc(duty.Slot))
		}
	}()

	switch duty.Type {
	case core.DutyAttester:
		att, err := core.DecodeAttestationAggSignedData(aggData)
		if err != nil {
			return err
		}

		err = b.eth2Cl.SubmitAttestations(ctx, []*eth2p0.Attestation{att})
		if err == nil {
			log.Info(ctx, "Attestation successfully submitted to beacon node",
				z.U64("slot", uint64(att.Data.Slot)),
				z.U64("target_epoch", uint64(att.Data.Target.Epoch)),
				z.Hex("agg_bits", att.AggregationBits.Bytes()),
				z.Any("pubkey", pubkey),
				z.Any("delay", b.delayFunc(duty.Slot)),
			)
		}

		return err
	case core.DutyProposer:
		block, err := core.DecodeBlockAggSignedData(aggData)
		if err != nil {
			return err
		}

		err = b.eth2Cl.SubmitBeaconBlock(ctx, block)
		if err == nil {
			log.Info(ctx, "Block proposal successfully submitted to beacon node",
				z.U64("slot", uint64(duty.Slot)),
				z.Any("pubkey", pubkey),
				z.Any("delay", b.delayFunc(duty.Slot)),
			)
		}

		return err

	case core.DutyExit:
		exit, err := core.DecodeExitAggSignedData(aggData)
		if err != nil {
			return err
		}

		err = b.eth2Cl.SubmitVoluntaryExit(ctx, exit)
		if err == nil {
			log.Info(ctx, "Voluntary exit successfully submitted to beacon node",
				z.U64("epoch", uint64(exit.Message.Epoch)),
				z.U64("validator_index", uint64(exit.Message.ValidatorIndex)),
				z.Any("pubkey", pubkey),
				z.Any("delay", b.delayFunc(duty.Slot)),
			)
		}

		return err
	case core.DutyRandao:
		// Randao is an internal duty, not broadcasted to beacon chain
		return nil
	default:
		return errors.New("unsupported duty type")
	}
}

// newDelayFunc returns a function that calculates the delay since the start of a slot.
func newDelayFunc(ctx context.Context, eth2Cl eth2Provider) (func(slot int64) time.Duration, error) {
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
