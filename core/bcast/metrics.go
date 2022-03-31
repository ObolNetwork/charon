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

package bcast

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/obolnetwork/charon/core"
)

var broadcastCounter = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "core",
	Subsystem: "bcast",
	Name:      "broadcast_total",
	Help:      "The total count of successfully broadcast duties by pubkey and type",
}, []string{"type", "pubkey"})

// instrumentDuty increments the duty counter.
func instrumentDuty(duty core.Duty, pubkey core.PubKey) {
	broadcastCounter.WithLabelValues(duty.Type.String(), pubkey.String()).Inc()
}
