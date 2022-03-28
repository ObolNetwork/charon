// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scheduler

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/obolnetwork/charon/core"
)

var (
	slotGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "core",
		Subsystem: "scheduler",
		Name:      "current_slot",
		Help:      "The current slot",
	})

	epochGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "core",
		Subsystem: "scheduler",
		Name:      "current_epoch",
		Help:      "The current epoch",
	})

	dutyCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "scheduler",
		Name:      "duty_total",
		Help:      "The total count of duties scheduled by pubkey and type",
	}, []string{"type", "pubkey"})
)

// instrumentSlot sets the current slot and epoch metrics.
func instrumentSlot(slot slot) {
	slotGauge.Set(float64(slot.Slot))
	epochGauge.Set(float64(slot.Epoch()))
}

// instrumentDuty increments the duty counter.
func instrumentDuty(duty core.Duty, argSet core.FetchArgSet) {
	for pubkey := range argSet {
		dutyCounter.WithLabelValues(duty.Type.String(), pubkey.String()).Inc()
	}
}
