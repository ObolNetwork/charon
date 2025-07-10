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

type ForkSchedule struct {
	Version eth2p0.Version
	Epoch   eth2p0.Epoch
}

type ForkForkSchedule map[Fork]ForkSchedule

type Fork uint64

const (
	Altair Fork = iota
	Bellatrix
	Capella
	Deneb
	Electra
	// Fulu
)

func (f Fork) String() string {
	return forkLabels[f]
}

var forkLabels = map[Fork]string{
	Altair:    "ALTAIR",
	Bellatrix: "BELLATRIX",
	Capella:   "CAPELLA",
	Deneb:     "DENEB",
	Electra:   "ELECTRA",
	// Fulu:      "FULU",
}

var (
	errFetchNetworkSpec   = errors.New("fetch network spec")
	errMissingNetworkSpec = errors.New("missing network spec")
)

func FetchGenesisTime(ctx context.Context, client eth2client.GenesisProvider) (time.Time, error) {
	genesisTime, err := client.Genesis(ctx, &api.GenesisOpts{})
	if err != nil {
		return time.Time{}, errFetchNetworkSpec
	}

	if genesisTime == nil {
		return time.Time{}, errMissingNetworkSpec
	}

	return genesisTime.Data.GenesisTime, nil
}

func FetchSlotsConfig(ctx context.Context, client eth2client.SpecProvider) (slotDuration time.Duration, slotsPerEpoch uint64, err error) {
	spec, err := client.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return 0, 0, errFetchNetworkSpec
	}

	if spec == nil {
		return 0, 0, errMissingNetworkSpec
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

	if slotDuration == 0 || slotsPerEpoch == 0 {
		return 0, 0, errors.New("zero slot duration or slots per epoch in network spec")
	}

	return slotDuration, slotsPerEpoch, nil
}

func FetchForkConfig(ctx context.Context, client eth2client.SpecProvider) (fork ForkForkSchedule, err error) {
	spec, err := client.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return nil, errFetchNetworkSpec
	}

	if spec == nil {
		return nil, errMissingNetworkSpec
	}

	res := ForkForkSchedule{}

	for k, v := range forkLabels {
		fs, err := fetchFork(v, spec.Data)
		if err != nil {
			return nil, err
		}

		res[k] = fs
	}

	return res, nil
}

func fetchFork(forkName string, data map[string]any) (ForkSchedule, error) {
	var ok bool

	fs := ForkSchedule{}
	forkVersion := forkName + "_FORK_VERSION"

	version, ok := data[forkVersion].(eth2p0.Version)
	if !ok {
		return fs, errors.New("missing " + forkVersion + " in network spec")
	}

	fs.Version = version

	forkEpoch := forkName + "_FORK_EPOCH"

	epoch, ok := data[forkEpoch].(uint64)
	if !ok {
		return fs, errors.New("missing " + forkEpoch + " in network spec")
	}

	fs.Epoch = eth2p0.Epoch(epoch)

	return fs, nil
}
