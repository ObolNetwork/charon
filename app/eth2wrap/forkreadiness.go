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
	forkStatusRestartRequired = "restart_required"
	forkStatusUpgradeRequired = "upgrade_required"
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

// StartForkReadinessMetric starts a goroutine that periodically compares the beacon node's
// current fork schedule against the schedule charon applied at startup, populating the fork
// readiness metrics and warning when charon requires a restart or an upgrade.
//
// go-eth2-client refreshes its cached network spec every 5 minutes, so each tick observes a
// recent spec even though charon's components only apply the spec at startup.
func StartForkReadinessMetric(ctx context.Context, client eth2client.SpecProvider,
	nodeVersions func(context.Context) []NodeClientVersions,
	vcUserAgents func() []string,
	clk clockwork.Clock,
) {
	go func() {
		applied, err := FetchForkConfig(ctx, client)
		if err != nil {
			log.Error(ctx, "Failed to fetch startup fork schedule for fork readiness metrics", err)
			return
		}

		for fork, fs := range applied {
			if fs.Epoch != math.MaxUint64 {
				appliedForkEpochGauge.WithLabelValues(forkMetricLabel(fork.String())).Set(float64(fs.Epoch))
			}
		}

		ticker := clk.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for {
			evaluateForkReadiness(ctx, client, nodeVersions, vcUserAgents, applied)

			select {
			case <-ctx.Done():
				return
			case <-ticker.Chan():
			}
		}
	}()
}

// evaluateForkReadiness populates the fork readiness metrics from the beacon node's current
// fork schedule and warns about forks that require a charon restart or upgrade.
func evaluateForkReadiness(ctx context.Context, client eth2client.SpecProvider,
	nodeVersions func(context.Context) []NodeClientVersions,
	vcUserAgents func() []string,
	applied ForkForkSchedule,
) {
	current, err := FetchForkConfig(ctx, client)
	if err != nil {
		log.Warn(ctx, "Failed to fetch current fork schedule for fork readiness metrics", err)
		return
	}

	specResp, err := client.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		log.Warn(ctx, "Failed to fetch network spec for fork readiness metrics", err)
		return
	}

	networkForkEpochGauge.Reset()
	forkReadinessGauge.Reset()

	versions := nodeVersions(ctx)
	vcAgents := vcUserAgents()

	for fork, cur := range current {
		var (
			label        = forkMetricLabel(fork.String())
			app          = applied[fork]
			curScheduled = cur.Epoch != math.MaxUint64
			appScheduled = app.Epoch != math.MaxUint64
		)

		if curScheduled {
			networkForkEpochGauge.WithLabelValues(label).Set(float64(cur.Epoch))
		}

		if !curScheduled && !appScheduled {
			continue // Fork not scheduled on the network, nothing to be ready for.
		}

		if cur == app {
			forkReadinessGauge.WithLabelValues(label, forkComponentCharon, forkStatusReady, "").Set(1)
		} else {
			forkReadinessGauge.WithLabelValues(label, forkComponentCharon, forkStatusRestartRequired, "").Set(1)
			log.Warn(ctx, "Beacon node fork schedule differs from the schedule charon applied at startup. Restart charon to apply the current fork schedule", nil,
				z.Str("fork", label),
				z.U64("network_epoch", uint64(cur.Epoch)),
				z.U64("applied_epoch", uint64(app.Epoch)))
		}

		if !curScheduled {
			continue // Client support only applies to forks scheduled on the network.
		}

		for _, nv := range versions {
			setClientForkReadiness(ctx, label, forkComponentBeaconNode, nv.Address, nv.BeaconNode,
				minimumBeaconNodeVersionByFork[fork],
				"Beacon node version does not support a scheduled fork. Upgrade the beacon node before the fork activates")

			setClientForkReadiness(ctx, label, forkComponentExecutionLayer, nv.Address, nv.ExecutionClient,
				minimumExecutionEngineVersionByFork[fork],
				"Execution engine version does not support a scheduled fork. Upgrade the execution engine before the fork activates")
		}

		for _, agent := range vcAgents {
			setClientForkReadiness(ctx, label, forkComponentValidatorClient, agent, agent,
				minimumValidatorClientVersionByFork[fork],
				"Validator client version does not support a scheduled fork. Upgrade the validator client before the fork activates")
		}
	}

	for name, epoch := range unknownScheduledForks(specResp.Data) {
		networkForkEpochGauge.WithLabelValues(name).Set(float64(epoch))
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
// component and warns if the client requires an upgrade for the fork. Empty client versions
// resolve to an unknown status.
func setClientForkReadiness(ctx context.Context, fork string, component string, instance string,
	clientVersion string, minVersions map[string]version.SemVer, upgradeMsg string,
) {
	status, clVer, minVer := forkStatusUnknown, "", ""
	if clientVersion != "" {
		status, clVer, minVer = checkClientForkSupport(minVersions, clientVersion)
	}

	forkReadinessGauge.WithLabelValues(fork, component, status, instance).Set(1)

	if status == forkStatusUpgradeRequired {
		log.Warn(ctx, upgradeMsg, nil,
			z.Str("fork", fork),
			z.Str("instance", instance),
			z.Str("client_version", clVer),
			z.Str("minimum_required", minVer))
	}
}
