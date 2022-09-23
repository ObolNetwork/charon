// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package app

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/dkg"
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
		Help:      "Set to 1 if monitoring api `/readyz` endpoint returned 200 or else 0",
	})

	lockHashGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "cluster",
		Name:      "lock_hash",
		Help:      "Constant gauge with label set to current cluster lock hash",
	}, []string{"lock_hash"})

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

func initStartupMetrics(lockHash, peerName string, threshold, numOperators, numValidators int, forkVersion []byte) error {
	startGauge.SetToCurrentTime()
	err := setNetworkGauge(forkVersion)
	if err != nil {
		return err
	}

	hash, _ := version.GitCommit()
	gitGauge.WithLabelValues(hash).Set(1)
	versionGauge.WithLabelValues(version.Version).Set(1)
	lockHashGauge.WithLabelValues(lockHash).Set(1)
	peerNameGauge.WithLabelValues(peerName).Set(1)

	thresholdGauge.Set(float64(threshold))
	operatorsGauge.Set(float64(numOperators))
	validatorsGauge.Set(float64(numValidators))

	return nil
}

// setNetworkGauge sets the gauge to the current network/chain (ex: goerli, mainnet etc.).
func setNetworkGauge(forkVersion []byte) error {
	network, err := dkg.ForkVersionToNetwork(forkVersion)
	if err != nil {
		return err
	}

	networkGauge.WithLabelValues(network)

	return nil
}
