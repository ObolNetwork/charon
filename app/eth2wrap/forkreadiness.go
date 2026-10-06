// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"math"
	"strings"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/jonboulle/clockwork"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
)

const (
	forkComponentCharon          = "charon"
	forkComponentBeaconNode      = "beacon_node"
	forkComponentValidatorClient = "validator_client"
	forkComponentExecutionLayer  = "execution_layer"

	forkStatusReady           = "ready"
	forkStatusUpgradeRequired = "upgrade_required"
	forkStatusKnownIssues     = "known_issues"
	forkStatusUnknown         = "unknown"
)

// NodeClientVersions holds the client versions reported by a configured beacon node.
// Empty versions indicate the version could not be determined.
type NodeClientVersions struct {
	// Address is the beacon node address.
	Address string
	// BeaconNode is the beacon node version string.
	BeaconNode string
	// ExecutionClient is the execution engine version string, only published by beacon
	// nodes supporting the node version V2 endpoint.
	ExecutionClient string
}

// StartForkReadinessMetric starts a goroutine that periodically populates the fork readiness
// metrics from the fork schedule charon applies, warning when a client or charon itself requires
// an upgrade for a scheduled fork.
func StartForkReadinessMetric(ctx context.Context, client eth2client.SpecProvider,
	forkSchedule func() ForkForkSchedule,
	nodeVersions func(context.Context) []NodeClientVersions,
	vcUserAgents func() []string,
	clk clockwork.Clock,
) {
	go func() {
		ticker := clk.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for {
			evaluateForkReadiness(ctx, client, nodeVersions, vcUserAgents, forkSchedule())

			select {
			case <-ctx.Done():
				return
			case <-ticker.Chan():
			}
		}
	}()
}

// evaluateForkReadiness populates the fork readiness metrics from the applied fork schedule and
// warns about forks that require an upgrade. Charon applies the schedule at runtime, so it is
// ready for every scheduled fork it knows about.
func evaluateForkReadiness(ctx context.Context, client eth2client.SpecProvider,
	nodeVersions func(context.Context) []NodeClientVersions,
	vcUserAgents func() []string,
	applied ForkForkSchedule,
) {
	specResp, err := client.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		log.Warn(ctx, "Failed to fetch network spec for fork readiness metrics", err)
		return
	}

	forkReadinessGauge.Reset()

	versions := nodeVersions(ctx)
	vcAgents := vcUserAgents()

	for fork, fs := range applied {
		if fs.Epoch == math.MaxUint64 {
			continue // Fork not scheduled on the network, nothing to be ready for.
		}

		label := forkMetricLabel(fork.String())

		forkReadinessGauge.WithLabelValues(label, forkComponentCharon, forkStatusReady, "").Set(1)

		for _, nv := range versions {
			setClientForkReadiness(ctx, label, forkComponentBeaconNode, nv.Address, nv.BeaconNode,
				minimumBeaconNodeVersionByFork[fork], knownBeaconNodeIssuesByFork[fork],
				"Beacon node version does not support a scheduled fork. Upgrade the beacon node before the fork activates")

			setClientForkReadiness(ctx, label, forkComponentExecutionLayer, nv.Address, nv.ExecutionClient,
				minimumExecutionEngineVersionByFork[fork], knownExecutionEngineIssuesByFork[fork],
				"Execution engine version does not support a scheduled fork. Upgrade the execution engine before the fork activates")
		}

		for _, agent := range vcAgents {
			setClientForkReadiness(ctx, label, forkComponentValidatorClient, agent, agent,
				minimumValidatorClientVersionByFork[fork], knownValidatorClientIssuesByFork[fork],
				"Validator client version does not support a scheduled fork. Upgrade the validator client before the fork activates")
		}
	}

	for name, epoch := range unknownScheduledForks(specResp.Data) {
		forkReadinessGauge.WithLabelValues(name, forkComponentCharon, forkStatusUpgradeRequired, "").Set(1)
		log.Warn(ctx, "Beacon node scheduled a fork that this charon version does not support. Upgrade charon before the fork activates", nil,
			z.Str("fork", name),
			z.U64("network_epoch", epoch))
	}
}

// unknownScheduledForks returns the scheduled forks in the network spec that are unknown to
// this charon version, mapped to their activation epochs.
func unknownScheduledForks(spec map[string]any) map[string]uint64 {
	resp := make(map[string]uint64)

	for key := range spec {
		name, ok := strings.CutSuffix(key, "_FORK_VERSION")
		if !ok || name == "GENESIS" || isKnownFork(name) {
			continue
		}

		epoch, ok := spec[name+"_FORK_EPOCH"].(uint64)
		if !ok || epoch == math.MaxUint64 {
			continue // Fork not scheduled.
		}

		resp[forkMetricLabel(name)] = epoch
	}

	return resp
}

// isKnownFork returns true if the provided fork name, as published in the network spec
// (e.g. "GLOAS"), is known to this charon version.
func isKnownFork(name string) bool {
	for _, label := range forkLabels {
		if label == name {
			return true
		}
	}

	return false
}

// forkMetricLabel returns the metric label for the provided spec fork name.
func forkMetricLabel(name string) string {
	return strings.ToLower(name)
}

// setClientForkReadiness sets the fork readiness gauge for a single client of the provided
// component and warns if the client requires an upgrade or has known issues for the fork.
// Empty client versions resolve to an unknown status.
func setClientForkReadiness(ctx context.Context, fork string, component string, instance string,
	clientVersion string, minVersions map[string]version.SemVer, issues map[string]knownIssue, upgradeMsg string,
) {
	status, clVer, minVer, issue := forkStatusUnknown, "", "", ""
	if clientVersion != "" {
		status, clVer, minVer, issue = checkClientForkSupport(minVersions, issues, clientVersion)
	}

	forkReadinessGauge.WithLabelValues(fork, component, status, instance).Set(1)

	switch status {
	case forkStatusUpgradeRequired:
		log.Warn(ctx, upgradeMsg, nil,
			z.Str("fork", fork),
			z.Str("instance", instance),
			z.Str("client_version", clVer),
			z.Str("minimum_required", minVer))
	case forkStatusKnownIssues:
		log.Warn(ctx, "Client version has known issues for a scheduled fork. Upgrade the client once a fixed version is released", nil,
			z.Str("fork", fork),
			z.Str("component", component),
			z.Str("instance", instance),
			z.Str("client_version", clVer),
			z.Str("issue", issue))
	default:
		// Ready and unknown statuses need no warning.
	}
}
