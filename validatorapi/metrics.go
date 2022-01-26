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

package validatorapi

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	apiLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "validatorapi",
		Name:      "request_latency_seconds",
		Help:      "The validatorapi request latencies in seconds by endpoint",
	}, []string{"endpoint"})

	apiErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "validatorapi",
		Name:      "request_error_total",
		Help:      "The total number of validatorapi request errors",
	}, []string{"endpoint", "status_code"})
)

func incAPIErrors(endpoint string, statusCode int) {
	apiErrors.WithLabelValues(endpoint, strconv.Itoa(statusCode)).Inc()
}

func observeAPILatency(endpoint string) func() {
	t0 := time.Now()
	return func() {
		apiLatency.WithLabelValues(endpoint).Observe(time.Since(t0).Seconds())
	}
}
