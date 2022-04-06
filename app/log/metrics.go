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
