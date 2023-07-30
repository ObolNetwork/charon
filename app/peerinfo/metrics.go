// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package peerinfo

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var (
	peerClockOffset = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace:   "app",
		Subsystem:   "peerinfo",
		Name:        "clock_offset_seconds",
		Help:        "Peer clock offset in seconds",
		ConstLabels: nil,
	}, []string{"peer"})

	peerVersion = promauto.NewResetGaugeVec(prometheus.GaugeOpts{
		Namespace:   "app",
		Subsystem:   "peerinfo",
		Name:        "version",
		Help:        "Constant gauge with version label set to peer's charon version.",
		ConstLabels: nil,
	}, []string{"peer", "version"})

	peerGitHash = promauto.NewResetGaugeVec(prometheus.GaugeOpts{
		Namespace:   "app",
		Subsystem:   "peerinfo",
		Name:        "git_commit",
		Help:        "Constant gauge with git_hash label set to peer's git commit hash.",
		ConstLabels: nil,
	}, []string{"peer", "git_hash"})

	peerStartGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "app",
		Subsystem: "peerinfo",
		Name:      "start_time_secs",
		Help:      "Constant gauge set to the peer start time of the binary in unix seconds",
	}, []string{"peer"})

	peerIndexGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "app",
		Subsystem: "peerinfo",
		Name:      "index",
		Help:      "Constant gauge set to the peer index in the cluster definition",
	}, []string{"peer"})

	peerCompatibleGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "app",
		Subsystem: "peerinfo",
		Name:      "version_support",
		Help:      "Set to 1 if the peer's version is supported by (compatible with) the current version, else 0 if unsupported.",
	}, []string{"peer"})
)
