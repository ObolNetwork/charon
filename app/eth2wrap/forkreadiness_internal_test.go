// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"maps"
	"math"
	"testing"

	"github.com/attestantio/go-eth2-client/api"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/version"
)

// testSpec returns a minimal network spec with all known forks scheduled at epoch 0 except
// the provided overrides.
func testSpec(overrides map[string]any) map[string]any {
	spec := map[string]any{"GENESIS_FORK_VERSION": eth2p0.Version{}}

	for fork, label := range forkLabels {
		spec[label+"_FORK_VERSION"] = eth2p0.Version{byte(fork)}
		spec[label+"_FORK_EPOCH"] = uint64(0)
	}

	maps.Copy(spec, overrides)

	return spec
}

func specProvider(spec map[string]any) stubSpecProvider {
	return stubSpecProvider{resp: &api.Response[map[string]any]{Data: spec}}
}

func TestEvaluateForkReadiness(t *testing.T) {
	tests := []struct {
		name    string
		applied map[string]any // Spec at charon startup.
		current map[string]any // Spec published by the beacon node now.
		fork    string
		status  string
	}{
		{
			name:    "ready",
			applied: testSpec(nil),
			current: testSpec(nil),
			fork:    "electra",
			status:  forkStatusReady,
		},
		{
			name:    "restart required",
			applied: testSpec(map[string]any{"GLOAS_FORK_EPOCH": uint64(math.MaxUint64)}),
			current: testSpec(map[string]any{"GLOAS_FORK_EPOCH": uint64(4096)}),
			fork:    "gloas",
			status:  forkStatusRestartRequired,
		},
		{
			name:    "upgrade required",
			applied: testSpec(nil),
			current: testSpec(map[string]any{
				"HEZE_FORK_VERSION": eth2p0.Version{0x90},
				"HEZE_FORK_EPOCH":   uint64(8192),
			}),
			fork:   "heze",
			status: forkStatusUpgradeRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applied, err := FetchForkConfig(t.Context(), specProvider(tt.applied))
			require.NoError(t, err)

			noVersions := func(context.Context) []NodeClientVersions { return nil }
			noAgents := func() []string { return nil }
			evaluateForkReadiness(t.Context(), specProvider(tt.current), noVersions, noAgents, applied)

			require.InDelta(t, 1,
				testutil.ToFloat64(forkReadinessGauge.WithLabelValues(tt.fork, forkComponentCharon, tt.status, "")), 0)
		})
	}
}

func TestUnknownScheduledForks(t *testing.T) {
	spec := testSpec(map[string]any{
		"HEZE_FORK_VERSION":  eth2p0.Version{0x90},   // Unknown scheduled fork.
		"HEZE_FORK_EPOCH":    uint64(8192),           // Unknown scheduled fork.
		"IZMIR_FORK_VERSION": eth2p0.Version{0xa0},   // Unknown unscheduled fork.
		"IZMIR_FORK_EPOCH":   uint64(math.MaxUint64), // Unknown unscheduled fork.
		"OSAKA_FORK_VERSION": eth2p0.Version{0xb0},   // Unknown fork without an epoch.
	})

	require.Equal(t, map[string]uint64{"heze": 8192}, unknownScheduledForks(spec))
}

func TestEvaluateBNForkReadiness(t *testing.T) {
	// Set a minimum Lighthouse version for the electra fork.
	minVersion, err := version.Parse("v9.0.1")
	require.NoError(t, err)

	minGeth, err := version.Parse("v1.16.7")
	require.NoError(t, err)

	oldBN, oldVC, oldEL := minimumBeaconNodeVersionByFork, minimumValidatorClientVersionByFork, minimumExecutionEngineVersionByFork
	minimumBeaconNodeVersionByFork = map[Fork]map[string]version.SemVer{Electra: {"Lighthouse": minVersion}}
	minimumValidatorClientVersionByFork = map[Fork]map[string]version.SemVer{Electra: {"Lighthouse": minVersion}}
	minimumExecutionEngineVersionByFork = map[Fork]map[string]version.SemVer{Electra: {"Geth": minGeth}}

	t.Cleanup(func() {
		minimumBeaconNodeVersionByFork, minimumValidatorClientVersionByFork, minimumExecutionEngineVersionByFork = oldBN, oldVC, oldEL
	})

	spec := testSpec(nil)

	applied, err := FetchForkConfig(t.Context(), specProvider(spec))
	require.NoError(t, err)

	versions := func(context.Context) []NodeClientVersions {
		return []NodeClientVersions{
			{Address: "bn1", BeaconNode: "Lighthouse/v9.0.1-abcdef", ExecutionClient: "Geth/v1.16.7/abcdef"}, // Meets the minimum.
			{Address: "bn2", BeaconNode: "Lighthouse/v9.0.0-abcdef"},                                         // Below the minimum, no EL version.
			{Address: "bn3", BeaconNode: "teku/v25.9.3", ExecutionClient: "Geth/v1.15.0/abcdef"},             // No BN expectation, EL below minimum.
			{Address: "bn4", BeaconNode: "custom-build"},                                                     // Unparsable version.
		}
	}

	agents := func() []string {
		return []string{
			"Lighthouse/v9.0.1-abcdef", // Meets the minimum.
			"Vouch/v1.12.0",            // No expectation set.
		}
	}

	evaluateForkReadiness(t.Context(), specProvider(spec), versions, agents, applied)

	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentBeaconNode, forkStatusReady, "bn1")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentBeaconNode, forkStatusUpgradeRequired, "bn2")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentBeaconNode, forkStatusReady, "bn3")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentBeaconNode, forkStatusUnknown, "bn4")), 0)

	// Execution layer rows.
	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentExecutionLayer, forkStatusReady, "bn1")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentExecutionLayer, forkStatusUnknown, "bn2")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentExecutionLayer, forkStatusUpgradeRequired, "bn3")), 0)

	// Validator client rows.
	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentValidatorClient, forkStatusReady, "Lighthouse/v9.0.1-abcdef")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentValidatorClient, forkStatusReady, "Vouch/v1.12.0")), 0)
}
