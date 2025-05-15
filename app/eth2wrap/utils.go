// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"

	"github.com/obolnetwork/charon/app/errors"
)

func FetchGenesisTime(ctx context.Context, client eth2client.GenesisProvider) (time.Time, error) {
	genesisTime, err := client.Genesis(ctx, &api.GenesisOpts{})
	if err != nil {
		return time.Time{}, errors.Wrap(err, "failed to fetch network spec")
	}

	if genesisTime == nil {
		return time.Time{}, errors.New("missing network spec")
	}

	return genesisTime.Data.GenesisTime, nil
}

func FetchSlotsConfig(ctx context.Context, client eth2client.SpecProvider) (slotDuration time.Duration, slotsPerEpoch uint64, err error) {
	spec, err := client.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return 0, 0, errors.Wrap(err, "failed to fetch network spec")
	}

	if spec == nil {
		return 0, 0, errors.New("missing network spec")
	}

	var ok bool
	slotDuration, ok = spec.Data["SECONDS_PER_SLOT"].(time.Duration)
	if !ok {
		return 0, 0, errors.New("missing SECONDS_PER_SLOT in network spec")
	}

	slotsPerEpoch, ok = spec.Data["SLOTS_PER_EPOCH"].(uint64)
	if !ok {
		return 0, 0, errors.New("missing SLOTS_PER_EPOCH in network spec")
	}

	return slotDuration, slotsPerEpoch, nil
}
