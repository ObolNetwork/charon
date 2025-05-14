// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
)

type NetworkSpec struct {
	GenesisTime   time.Time
	SlotDuration  time.Duration
	SlotsPerEpoch uint64
}

// EpochSlot converts an epoch number to its first slot number.
func (ns *NetworkSpec) EpochSlot(epoch eth2p0.Epoch) eth2p0.Slot {
	return eth2p0.Slot(epoch) * eth2p0.Slot(ns.SlotsPerEpoch)
}

// SlotEpoch converts a slot number to its epoch number.
func (ns *NetworkSpec) SlotEpoch(slot eth2p0.Slot) eth2p0.Epoch {
	return eth2p0.Epoch(slot) / eth2p0.Epoch(ns.SlotsPerEpoch)
}

// FetchNetworkSpec retrieves the network specification from the eth2 client.
func FetchNetworkSpec(ctx context.Context, client eth2client.SpecProvider) (NetworkSpec, error) {
	spec, err := client.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return NetworkSpec{}, errors.Wrap(err, "failed to fetch network spec")
	}

	if spec == nil {
		return NetworkSpec{}, errors.New("missing network spec")
	}

	genesisTime, ok := spec.Data["MIN_GENESIS_TIME"].(time.Time)
	if !ok {
		return NetworkSpec{}, errors.New("missing MIN_GENESIS_TIME in network spec")
	}

	slotDuration, ok := spec.Data["SECONDS_PER_SLOT"].(time.Duration)
	if !ok {
		return NetworkSpec{}, errors.New("missing SECONDS_PER_SLOT in network spec")
	}

	slotsPerEpoch, ok := spec.Data["SLOTS_PER_EPOCH"].(uint64)
	if !ok {
		return NetworkSpec{}, errors.New("missing SLOTS_PER_EPOCH in network spec")
	}

	return NetworkSpec{
		GenesisTime:   genesisTime,
		SlotDuration:  slotDuration,
		SlotsPerEpoch: slotsPerEpoch,
	}, nil
}
