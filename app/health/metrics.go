// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package health

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var checkGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: "app",
	Subsystem: "health",
	Name:      "checks",
	Help:      "Application health checks by name and severity. Set to 1 for failing, 0 for ok.",
}, []string{"severity", "name"})
