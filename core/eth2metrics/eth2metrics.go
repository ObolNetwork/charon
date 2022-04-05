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

package eth2metrics

import (
	"context"
	"time"

	eth2http "github.com/attestantio/go-eth2-client/http"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/obolnetwork/charon/app/errors"
)

//go:generate go run genmetrics/genmetrics.go

var (
	latencyHist = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "core",
		Subsystem: "eth2",
		Name:      "latency_seconds",
		Help:      "Latency in seconds for eth2 beacon node requests",
	}, []string{"endpoint"})

	errorCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "eth2",
		Name:      "errors_total",
		Help:      "Total number of errors returned by eth2 beacon node requests",
	}, []string{"endpoint"})
)

// NewHTTPService returns a new instrumented eth2 http service.
func NewHTTPService(ctx context.Context, params ...eth2http.Parameter) (*Service, error) {
	eth2Svc, err := eth2http.New(ctx, params...)
	if err != nil {
		return nil, errors.Wrap(err, "new et2http")
	}

	eth2Cl, ok := eth2Svc.(*eth2http.Service)
	if !ok {
		return nil, errors.New("invalid eth2http service")
	}

	return &Service{Service: eth2Cl}, nil
}

// Service wraps an eth2http.Service adding prometheus metrics.
type Service struct {
	*eth2http.Service
}

// instrument instruments the endpoint.
// Usage:
//  defer instrument("endpoint")(err)
func instrument(endpoint string) func(err error) {
	t0 := time.Now()
	return func(err error) {
		latencyHist.WithLabelValues(endpoint).Observe(time.Since(t0).Seconds())
		if err != nil {
			errorCount.WithLabelValues(endpoint).Inc()
		}
	}
}
