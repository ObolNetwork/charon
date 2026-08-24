// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"math"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

type ForkSchedule struct {
	Version eth2p0.Version
	Epoch   eth2p0.Epoch
}

type ForkForkSchedule map[Fork]ForkSchedule

// Active returns true if the fork is scheduled and active at the provided epoch.
func (s ForkForkSchedule) Active(fork Fork, epoch eth2p0.Epoch) bool {
	fs, ok := s[fork]

	return ok && fs.Epoch != math.MaxUint64 && epoch >= fs.Epoch
}

type Fork uint64

const (
	Altair Fork = iota
	Bellatrix
	Capella
	Deneb
	Electra
	Fulu
	Gloas
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
	Fulu:      "FULU",
	Gloas:     "GLOAS",
}

// optionalForks are future forks that beacon nodes may not publish spec keys for yet.
// Missing spec keys resolve to an unscheduled fork instead of an error.
var optionalForks = map[Fork]bool{
	Gloas: true,
}

// Sentinel errors are wrapped when first returned so that the stack trace and the wrapping message
// identify which network spec fetch failed.
var (
	errFetchNetworkSpec   = errors.NewSentinel("fetch network spec")
	errMissingNetworkSpec = errors.NewSentinel("missing network spec")
)

// BasisPoints is the total number of basis points, ie. 100% of the slot duration.
const BasisPoints = 10_000

// ForkBPS defines an intra-slot duty deadline in basis points of the slot duration, per fork.
// PreGloas is zero for deadlines that the gloas fork introduces, since they don't apply before it.
type ForkBPS struct {
	PreGloas uint64
	Gloas    uint64
}

// SlotTimingConfig defines the network's intra-slot duty deadlines in basis points of the slot duration.
type SlotTimingConfig struct {
	Attestation  ForkBPS
	Aggregate    ForkBPS
	SyncMessage  ForkBPS
	Contribution ForkBPS
	// Payload is the deadline for the builder to reveal the execution payload.
	Payload ForkBPS
	// PayloadAttestation is the deadline for payload timeliness committee members to broadcast
	// payload attestations.
	PayloadAttestation ForkBPS
	// GloasEpoch is the epoch at which the gloas deadlines take effect. It is math.MaxUint64
	// if the beacon node doesn't publish GLOAS_FORK_EPOCH or hasn't scheduled the fork.
	GloasEpoch eth2p0.Epoch
}

// Intra-slot duty deadlines as basis points of the slot duration as defined by the consensus spec.
// These are applied for beacon nodes that predate the corresponding spec keys.
var (
	defaultAttestationBPS        = ForkBPS{PreGloas: 3333, Gloas: 2500}
	defaultAggregateBPS          = ForkBPS{PreGloas: 6667, Gloas: 5000}
	defaultSyncMessageBPS        = ForkBPS{PreGloas: 3333, Gloas: 2500}
	defaultContributionBPS       = ForkBPS{PreGloas: 6667, Gloas: 5000}
	defaultPayloadBPS            = ForkBPS{Gloas: 5000}
	defaultPayloadAttestationBPS = ForkBPS{Gloas: 7500}
)

// FetchSlotTimingConfig returns the network's intra-slot duty deadlines.
func FetchSlotTimingConfig(ctx context.Context, client eth2client.SpecProvider) (SlotTimingConfig, error) {
	spec, err := client.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return SlotTimingConfig{}, errors.Wrap(errFetchNetworkSpec, "fetch slot timing config")
	}

	if spec == nil {
		return SlotTimingConfig{}, errors.Wrap(errMissingNetworkSpec, "fetch slot timing config")
	}

	return parseSlotTimingConfig(spec.Data)
}

// parseSlotTimingConfig returns the intra-slot duty deadlines in the network spec data,
// defaulting to the consensus spec values for keys the beacon node doesn't publish.
func parseSlotTimingConfig(data map[string]any) (SlotTimingConfig, error) {
	resp := SlotTimingConfig{GloasEpoch: math.MaxUint64}

	if epoch, ok := data["GLOAS_FORK_EPOCH"].(uint64); ok {
		resp.GloasEpoch = eth2p0.Epoch(epoch)
	}

	// Note that the deadlines introduced by the gloas fork have no pre-gloas key, since the
	// unsuffixed key is itself the gloas value.
	for _, field := range []struct {
		PreGloasKey string
		GloasKey    string
		Default     ForkBPS
		Resolved    *ForkBPS
	}{
		{PreGloasKey: "ATTESTATION_DUE_BPS", GloasKey: "ATTESTATION_DUE_BPS_GLOAS", Default: defaultAttestationBPS, Resolved: &resp.Attestation},
		{PreGloasKey: "AGGREGATE_DUE_BPS", GloasKey: "AGGREGATE_DUE_BPS_GLOAS", Default: defaultAggregateBPS, Resolved: &resp.Aggregate},
		{PreGloasKey: "SYNC_MESSAGE_DUE_BPS", GloasKey: "SYNC_MESSAGE_DUE_BPS_GLOAS", Default: defaultSyncMessageBPS, Resolved: &resp.SyncMessage},
		{PreGloasKey: "CONTRIBUTION_DUE_BPS", GloasKey: "CONTRIBUTION_DUE_BPS_GLOAS", Default: defaultContributionBPS, Resolved: &resp.Contribution},
		{GloasKey: "PAYLOAD_DUE_BPS", Default: defaultPayloadBPS, Resolved: &resp.Payload},
		{GloasKey: "PAYLOAD_ATTESTATION_DUE_BPS", Default: defaultPayloadAttestationBPS, Resolved: &resp.PayloadAttestation},
	} {
		resolved := field.Default

		if field.PreGloasKey != "" {
			preGloas, err := parseBPS(data, field.PreGloasKey, field.Default.PreGloas)
			if err != nil {
				return SlotTimingConfig{}, err
			}

			resolved.PreGloas = preGloas
		}

		gloas, err := parseBPS(data, field.GloasKey, field.Default.Gloas)
		if err != nil {
			return SlotTimingConfig{}, err
		}

		resolved.Gloas = gloas

		*field.Resolved = resolved
	}

	return resp, nil
}

// parseBPS returns the basis points at the key in the network spec data,
// or def if the beacon node doesn't publish it.
func parseBPS(data map[string]any, key string, def uint64) (uint64, error) {
	bps, ok := data[key].(uint64)
	if !ok {
		return def, nil
	}

	if bps == 0 || bps > BasisPoints {
		return 0, errors.New("invalid basis points in network spec", z.Str("key", key), z.U64("bps", bps))
	}

	return bps, nil
}

func FetchGenesisTime(ctx context.Context, client eth2client.GenesisProvider) (time.Time, error) {
	genesisTime, err := client.Genesis(ctx, &api.GenesisOpts{})
	if err != nil {
		return time.Time{}, errors.Wrap(errFetchNetworkSpec, "fetch genesis time")
	}

	if genesisTime == nil {
		return time.Time{}, errors.Wrap(errMissingNetworkSpec, "fetch genesis time")
	}

	return genesisTime.Data.GenesisTime, nil
}

func FetchSlotsConfig(ctx context.Context, client eth2client.SpecProvider) (slotDuration time.Duration, slotsPerEpoch uint64, err error) {
	spec, err := client.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return 0, 0, errors.Wrap(errFetchNetworkSpec, "fetch slots config")
	}

	if spec == nil {
		return 0, 0, errors.Wrap(errMissingNetworkSpec, "fetch slots config")
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
		return nil, errors.Wrap(errFetchNetworkSpec, "fetch fork config")
	}

	if spec == nil {
		return nil, errors.Wrap(errMissingNetworkSpec, "fetch fork config")
	}

	res := ForkForkSchedule{}

	for k, v := range forkLabels {
		fs, err := fetchFork(v, spec.Data, optionalForks[k])
		if err != nil {
			return nil, err
		}

		res[k] = fs
	}

	return res, nil
}

// fetchFork returns the fork schedule of the named fork from the network spec.
// Optional (future) forks tolerate missing spec keys and resolve to an unscheduled
// fork with an epoch of math.MaxUint64, consistent with how beacon nodes publish
// unscheduled forks.
func fetchFork(forkName string, data map[string]any, optional bool) (ForkSchedule, error) {
	var ok bool

	fs := ForkSchedule{Epoch: math.MaxUint64}
	forkVersion := forkName + "_FORK_VERSION"

	version, ok := data[forkVersion].(eth2p0.Version)
	if !ok && !optional {
		return fs, errors.New("missing " + forkVersion + " in network spec")
	}

	fs.Version = version

	forkEpoch := forkName + "_FORK_EPOCH"

	epoch, ok := data[forkEpoch].(uint64)
	if !ok && !optional {
		return fs, errors.New("missing " + forkEpoch + " in network spec")
	}

	if ok {
		fs.Epoch = eth2p0.Epoch(epoch)
	}

	return fs, nil
}
