// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package forkschedule

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var (
	currentForkGauge = promauto.NewResetGaugeVec(prometheus.GaugeOpts{
		Namespace: "app",
		Subsystem: "fork",
		Name:      "current_activation_epoch",
		Help:      "Constant gauge with the epoch at which the current fork activated, labelled by the fork name, e.g. gloas",
	}, []string{"fork"})

	nextForkGauge = promauto.NewResetGaugeVec(prometheus.GaugeOpts{
		Namespace: "app",
		Subsystem: "fork",
		Name:      "next_activation_epoch",
		Help:      "Constant gauge with the epoch at which the next scheduled fork activates, labelled by the fork name, e.g. heze. Absent if no fork is scheduled",
	}, []string{"fork"})

	scheduleConflictGauge = promauto.NewResetGaugeVec(prometheus.GaugeOpts{
		Namespace: "app",
		Subsystem: "fork",
		Name:      "schedule_conflict",
		Help:      "Constant gauge set to 1 for a fork the beacon nodes schedule at different epochs, of which the earliest is applied, labelled by the fork name. Absent if they agree",
	}, []string{"fork"})
)
