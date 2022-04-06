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
)

var (
	versionGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "app",
		Name:      "version",
		Help:      "Constant gauge with label set to current app version",
	}, []string{"version"})

	startGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "app",
		Name:      "start_time_secs",
		Help:      "Gauge set to the app start time of the binary in unix seconds",
	})
)

func initStartupMetrics() {
	versionGauge.WithLabelValues(version.Version).Set(1)
	startGauge.SetToCurrentTime()
}
