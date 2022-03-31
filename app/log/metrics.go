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

package log

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	errorCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "app",
		Subsystem: "log",
		Name:      "error_total",
		Help:      "Total count of logged errors by topic",
	}, []string{"topic"})

	warnCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace:   "app",
		Subsystem:   "log",
		Name:        "warn_total",
		Help:        "Total count of logged warnings by topic",
		ConstLabels: nil,
	}, []string{"topic"})
)

func incWarnCounter(ctx context.Context) {
	warnCounter.WithLabelValues(metricsTopicFromCtx(ctx)).Inc()
}

func incErrorCounter(ctx context.Context) {
	errorCounter.WithLabelValues(metricsTopicFromCtx(ctx)).Inc()
}
