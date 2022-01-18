package runner

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	versionGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "runner",
		Name:      "version",
		Help:      "Constant gauge with label set to current version",
	}, []string{"version"})

	startGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "runner",
		Name:      "start_time_secs",
		Help:      "Gauge set to the start time of the binary in unix seconds",
	})
)
