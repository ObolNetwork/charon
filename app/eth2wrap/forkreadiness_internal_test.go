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
		applied map[string]any // Spec of the fork schedule charon applies.
		current map[string]any // Spec published by the beacon node.
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
			name:    "ready for a fork scheduled at runtime",
			applied: testSpec(map[string]any{"GLOAS_FORK_EPOCH": uint64(4096)}),
			current: testSpec(map[string]any{"GLOAS_FORK_EPOCH": uint64(math.MaxUint64)}),
			fork:    "gloas",
			status:  forkStatusReady,
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
	minVersion := mustParseForkVersion("v9.0.1")
	minGeth := mustParseForkVersion("v1.16.7")
	minTeku := mustParseForkVersion("v25.9.3")
	fixedTeku := mustParseForkVersion("v25.10.0")

	oldBN, oldVC, oldEL := minimumBeaconNodeVersionByFork, minimumValidatorClientVersionByFork, minimumExecutionEngineVersionByFork
	oldBNIssues, oldVCIssues, oldELIssues := knownBeaconNodeIssuesByFork, knownValidatorClientIssuesByFork, knownExecutionEngineIssuesByFork
	minimumBeaconNodeVersionByFork = map[Fork]map[string]forkVersion{Electra: {"lighthouse": minVersion}}
	minimumValidatorClientVersionByFork = map[Fork]map[string]forkVersion{Electra: {"lighthouse": minVersion, "teku": minTeku}}
	minimumExecutionEngineVersionByFork = map[Fork]map[string]forkVersion{Electra: {"go-ethereum": minGeth}}
	knownBeaconNodeIssuesByFork = map[Fork]map[string]knownIssue{}
	knownValidatorClientIssuesByFork = map[Fork]map[string]knownIssue{Electra: {"teku": {Description: "bug", FixedIn: fixedTeku}}}
	knownExecutionEngineIssuesByFork = map[Fork]map[string]knownIssue{Electra: {"go-ethereum": {Description: "unfixed bug"}}}

	t.Cleanup(func() {
		minimumBeaconNodeVersionByFork, minimumValidatorClientVersionByFork, minimumExecutionEngineVersionByFork = oldBN, oldVC, oldEL
		knownBeaconNodeIssuesByFork, knownValidatorClientIssuesByFork, knownExecutionEngineIssuesByFork = oldBNIssues, oldVCIssues, oldELIssues
	})

	spec := testSpec(nil)

	applied, err := FetchForkConfig(t.Context(), specProvider(spec))
	require.NoError(t, err)

	versions := func(context.Context) []NodeClientVersions {
		return []NodeClientVersions{
			{Address: "bn1", BeaconNode: "Lighthouse/v9.0.1-abcdef", ExecutionClient: "Reth/2.7.0/abcdef"}, // Meets the minimum, no EL expectation.
			{Address: "bn2", BeaconNode: "Lighthouse/v9.0.0-abcdef"},                                       // Below the minimum, no EL version.
			{Address: "bn3", BeaconNode: "teku/v25.9.3", ExecutionClient: "Geth/v1.15.0/abcdef"},           // No BN expectation, EL below minimum.
			{Address: "bn4", BeaconNode: "custom-build", ExecutionClient: "Geth/1.16.7-stable/abcdef"},     // Unparsable version, EL with unfixed issue.
		}
	}

	agents := func() []string {
		return []string{
			"Lighthouse/v9.0.1-abcdef", // Meets the minimum.
			"Vouch/v1.12.0",            // No expectation set.
			"teku/v25.9.3",             // Issue fixed in a later version.
			"teku/v25.10.0",            // Issue fixed.
			"unknown",                  // No user agent.
		}
	}

	evaluateForkReadiness(t.Context(), specProvider(spec), versions, agents, applied)

	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentBeaconNode, forkStatusReady, "bn1")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentBeaconNode, forkStatusUpgradeRequired, "bn2")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentBeaconNode, forkStatusUnknown, "bn3")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentBeaconNode, forkStatusUnknown, "bn4")), 0)

	// Execution layer rows.
	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentExecutionLayer, forkStatusUnknown, "bn1")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentExecutionLayer, forkStatusUnknown, "bn2")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentExecutionLayer, forkStatusUpgradeRequired, "bn3")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentExecutionLayer, forkStatusKnownIssues, "bn4")), 0)

	// Validator client rows.
	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentValidatorClient, forkStatusReady, "Lighthouse/v9.0.1-abcdef")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentValidatorClient, forkStatusUnknown, "Vouch/v1.12.0")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentValidatorClient, forkStatusKnownIssues, "teku/v25.9.3")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentValidatorClient, forkStatusReady, "teku/v25.10.0")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(forkReadinessGauge.WithLabelValues("electra", forkComponentValidatorClient, forkStatusUnknown, "unknown")), 0)
}

func TestGloasClientVersions(t *testing.T) {
	tests := []struct {
		minVersions map[string]forkVersion
		issues      map[string]knownIssue
		version     string
		status      string
	}{
		{minimumBeaconNodeVersionByFork[Gloas], knownBeaconNodeIssuesByFork[Gloas], "Lighthouse/v8.3.0-rc.0-4920af7/x86_64-linux", forkStatusReady},
		{minimumBeaconNodeVersionByFork[Gloas], knownBeaconNodeIssuesByFork[Gloas], "Lighthouse/v8.3.0-rc.1-4920af7/x86_64-linux", forkStatusReady},
		{minimumBeaconNodeVersionByFork[Gloas], knownBeaconNodeIssuesByFork[Gloas], "Lighthouse/v8.3.0-4920af7/x86_64-linux", forkStatusReady},
		{minimumBeaconNodeVersionByFork[Gloas], knownBeaconNodeIssuesByFork[Gloas], "Lighthouse/v8.3.1-beta.0/x86_64-linux", forkStatusReady},
		{minimumBeaconNodeVersionByFork[Gloas], knownBeaconNodeIssuesByFork[Gloas], "Lighthouse/v8.3.0-beta.1-4920af7/x86_64-linux", forkStatusUpgradeRequired},
		{minimumBeaconNodeVersionByFork[Gloas], knownBeaconNodeIssuesByFork[Gloas], "Lighthouse/v8.2.1-abcdef/x86_64-linux", forkStatusUpgradeRequired},
		{minimumBeaconNodeVersionByFork[Gloas], knownBeaconNodeIssuesByFork[Gloas], "Lodestar/v1.49.0-rc.1/0e1dc85", forkStatusUpgradeRequired},
		{minimumBeaconNodeVersionByFork[Gloas], knownBeaconNodeIssuesByFork[Gloas], "Prysm/v7.2.1-RC0/fea24b4", forkStatusUpgradeRequired},
		{minimumBeaconNodeVersionByFork[Gloas], knownBeaconNodeIssuesByFork[Gloas], "Prysm/v7.2.0/fea24b4", forkStatusUpgradeRequired},
		{minimumBeaconNodeVersionByFork[Gloas], knownBeaconNodeIssuesByFork[Gloas], "Grandine/3.0.0/e3ce4d43", forkStatusUnknown},
		{minimumValidatorClientVersionByFork[Gloas], knownValidatorClientIssuesByFork[Gloas], "Lodestar/v1.49.0/0e1dc85", forkStatusReady},
		{minimumValidatorClientVersionByFork[Gloas], knownValidatorClientIssuesByFork[Gloas], "Nimbus/v26.10.0-657beb-stateofus", forkStatusReady},
		{minimumValidatorClientVersionByFork[Gloas], knownValidatorClientIssuesByFork[Gloas], "Prysm/v7.2.1/fea24b41265542905352ab45fe2291d8eea010cc", forkStatusReady},
		{minimumValidatorClientVersionByFork[Gloas], knownValidatorClientIssuesByFork[Gloas], "teku/v26.9.1", forkStatusKnownIssues},
		{minimumExecutionEngineVersionByFork[Gloas], knownExecutionEngineIssuesByFork[Gloas], "go-ethereum/1.17.7-stable/3d858f85", forkStatusReady},
		{minimumExecutionEngineVersionByFork[Gloas], knownExecutionEngineIssuesByFork[Gloas], "Reth/2.7.0/3d592ece", forkStatusReady},
		{minimumExecutionEngineVersionByFork[Gloas], knownExecutionEngineIssuesByFork[Gloas], "reth/v2.5.2/3d592ece", forkStatusUpgradeRequired},
		{minimumExecutionEngineVersionByFork[Gloas], knownExecutionEngineIssuesByFork[Gloas], "Geth/v1.16.8-stable/abcdef12", forkStatusUpgradeRequired},
		{minimumExecutionEngineVersionByFork[Gloas], knownExecutionEngineIssuesByFork[Gloas], "Geth/v1.17.7-stable/abcdef12", forkStatusReady},
		{minimumExecutionEngineVersionByFork[Gloas], knownExecutionEngineIssuesByFork[Gloas], "Nethermind/2.1.0+abcdef1/abcdef12", forkStatusReady},
		{minimumExecutionEngineVersionByFork[Gloas], knownExecutionEngineIssuesByFork[Gloas], "erigon/3.7.0-abcdef12/abcdef12", forkStatusReady},
		{minimumExecutionEngineVersionByFork[Gloas], knownExecutionEngineIssuesByFork[Gloas], "ethrex/v28.0.0/abcdef12", forkStatusReady},
		{minimumExecutionEngineVersionByFork[Gloas], knownExecutionEngineIssuesByFork[Gloas], "Besu/26.8.0/abcdef12", forkStatusUpgradeRequired},
		{minimumBeaconNodeVersionByFork[Fulu], knownBeaconNodeIssuesByFork[Fulu], "Grandine/3.0.0/e3ce4d43", forkStatusReady}, // No expectations for the fork.
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			status, _, _, _ := checkClientForkSupport(tt.minVersions, tt.issues, tt.version)
			require.Equal(t, tt.status, status)
		})
	}
}

func TestParseClientForkVersion(t *testing.T) {
	tests := []struct {
		input  string
		client string
		want   string
	}{
		{"Lighthouse/v8.3.0-rc.0-4920af7/x86_64-linux", "Lighthouse", "v8.3.0-rc.0"},
		{"Nimbus/v26.10.0-657beb-stateofus", "Nimbus", "v26.10.0"},
		{"Lodestar/v1.49.0/0e1dc85", "Lodestar", "v1.49.0"},
		{"Nethermind/2.1.0+abcdef1/abcdef12", "Nethermind", "v2.1.0"},
		{"Grandine/v2.0.0.rc0", "Grandine", "v2.0.0-rc.0"},
		{"teku/v26.9.1-rc1", "teku", "v26.9.1-rc.1"},
		{"teku/v26.9.1-rc-2", "teku", "v26.9.1-rc.2"},
		{"teku/v26.9.1-RC", "teku", "v26.9.1-rc.0"},
		{"teku/v26.9.1-alpha3", "teku", "v26.9.1-alpha.3"},
		{"teku/v26.9.1-beta.4", "teku", "v26.9.1-beta.4"},
		{"teku/v26.9.1-dev", "teku", "v26.9.1"},
		{"v8.3.0-rc.0", "", "v8.3.0-rc.0"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			client, v, ok := parseClientForkVersion(tt.input)
			require.True(t, ok)
			require.Equal(t, tt.client, client)
			require.Equal(t, tt.want, v.String())
		})
	}

	_, _, ok := parseClientForkVersion("custom-build")
	require.False(t, ok)
}

func TestIsValidatorClientUserAgent(t *testing.T) {
	for _, ua := range []string{"Lighthouse/v8.3.0", "teku/v26.9.1", "Lodestar/v1.49.0/0e1dc85", "Nimbus/v26.10.0-657beb-stateofus", "Prysm/v7.2.1/fea24b4", "Vouch/1.12.0"} {
		require.True(t, IsValidatorClientUserAgent(ua), ua)
	}

	for _, ua := range []string{"Grafana/10.4.0", "axios/1.7.2", "curl/8.5.0", "Go-http-client/1.1", "nim-presto/0.0.3", "teku", ""} {
		require.False(t, IsValidatorClientUserAgent(ua), ua)
	}
}
