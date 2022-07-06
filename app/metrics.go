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
	"runtime/debug"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/obolnetwork/charon/app/version"
)

var (
	versionGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "app",
		Name:      "version",
		Help:      "Constant gauge with label set to current app version",
	}, []string{"version"})

	gitGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "app",
		Name:      "git_commit",
		Help:      "Constant gauge with label set to current git commit hash",
	}, []string{"hash"})

	startGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "app",
		Name:      "start_time_secs",
		Help:      "Gauge set to the app start time of the binary in unix seconds",
	})

	livezGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "app",
		Subsystem: "monitoring",
		Name:      "livez",
		Help:      "Set to 1 if `/livez` endpoint returns 200, 0 otherwise",
	})

	readyzGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "app",
		Subsystem: "monitoring",
		Name:      "readyz",
		Help:      "Set to 1 if `/readyz` endpoint returns 200, 0 otherwise",
	})
)

func initStartupMetrics() {
	versionGauge.WithLabelValues(version.Version).Set(1)
	startGauge.SetToCurrentTime()
	livezGauge.Set(1)
	readyzGauge.Set(1)

	hash, _ := GitCommit()
	gitGauge.WithLabelValues(hash).Set(1)
}

// GitCommit returns the git commit hash and timestamp from build info.
func GitCommit() (hash string, timestamp string) {
	hash, timestamp = "unknown", "unknown"

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return hash, timestamp
	}

	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			hash = s.Value[:7]
		} else if s.Key == "vcs.time" {
			timestamp = s.Value
		}
	}

	return hash, timestamp
}
