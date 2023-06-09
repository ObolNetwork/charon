// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
	"github.com/obolnetwork/charon/app/version"
)

const (
	// readyzReady indicates that readyz returns 200s and the node is operational.
	readyzReady = 1
	// readyzBeaconNodeDown indicates that readyz is returning 500s since the Beacon Node API is down.
	readyzBeaconNodeDown = 2
	// readyzBeaconNodeSyncing indicates that readyz is returning 500s since the Beacon Node is syncing.
	readyzBeaconNodeSyncing = 3
	// readyzInsufficientPeers indicates that readyz is returning 500s since this node isn't connected
	// to quorum peers via the P2P network.
	readyzInsufficientPeers = 4
	// readyzVCNotConnected indicates that readyz is returning 500s since VC is connected to this node.
	readyzVCNotConnected = 5
	// readyVCMissingValidators indicates that readyz is returning 500s since VC is not configured correctly
	// and missing some/all validators.
	readyzVCMissingValidators = 6
	// readyzBeaconNodeZeroPeers indicates that readyz is returning 500s since the Beacon Node has zero peers
	// and hence cannot sync.
	readyzBeaconNodeZeroPeers = 7
	// readyzBeaconNodeFarBehind indicates that readyz is returning 500s since the Beacon Node is too far behind
	// the head slot.
	readyzBeaconNodeFarBehind = 8
)

var (
	versionGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "app",
		Name:      "version",
		Help:      "Constant gauge with label set to current app version",
	}, []string{"version"})

	peerNameGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "app",
		Name:      "peer_name",
		Help:      "Constant gauge with label set to the name of the cluster peer",
	}, []string{"peer_name"})

	gitGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "app",
		Name:      "git_commit",
		Help:      "Constant gauge with label set to current git commit hash",
	}, []string{"git_hash"})

	startGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "app",
		Name:      "start_time_secs",
		Help:      "Gauge set to the app start time of the binary in unix seconds",
	})

	readyzGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "app",
		Subsystem: "monitoring",
		Name:      "readyz",
		Help: "Set to 1 if the node is operational and monitoring api `/readyz` endpoint is returning 200s. " +
			"Else `/readyz` is returning 500s and this metric is either set to " +
			"2 if the beacon node is down, or" +
			"3 if the beacon node is syncing, or" +
			"4 if quorum peers are not connected.",
	})

	beaconNodePeerCountGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "app",
		Subsystem: "beacon_node",
		Name:      "peers",
		Help:      "Gauge set to the peer count of the upstream beacon node",
	})

	beaconNodeVersionGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "app",
		Subsystem: "beacon_node",
		Name:      "version",
		Help:      "Constant gauge with label set to the node version of the upstream beacon node",
	}, []string{"version"})

	thresholdGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "cluster",
		Name:      "threshold",
		Help:      "Aggregation threshold in the cluster lock",
	})

	operatorsGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "cluster",
		Name:      "operators",
		Help:      "Number of operators in the cluster lock",
	})

	validatorsGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "cluster",
		Name:      "validators",
		Help:      "Number of validators in the cluster lock",
	})

	networkGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "cluster",
		Name:      "network",
		Help:      "Constant gauge with label set to the current network (chain)",
	}, []string{"network"})
)

func initStartupMetrics(peerName string, threshold, numOperators, numValidators int, network string) {
	startGauge.SetToCurrentTime()
	networkGauge.WithLabelValues(network).Set(1)

	hash, _ := version.GitCommit()
	gitGauge.WithLabelValues(hash).Set(1)
	versionGauge.WithLabelValues(version.Version.String()).Set(1)
	peerNameGauge.WithLabelValues(peerName).Set(1)

	thresholdGauge.Set(float64(threshold))
	operatorsGauge.Set(float64(numOperators))
	validatorsGauge.Set(float64(numValidators))
}
