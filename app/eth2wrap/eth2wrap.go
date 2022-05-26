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

// Package eth2wrap provides a wrapper for eth2http.Service adding prometheus metrics and error wrapping.
package eth2wrap

import (
	"context"
	"time"

	eth2http "github.com/attestantio/go-eth2-client/http"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/obolnetwork/charon/app/errors"
)

//go:generate go run genwrap/genwrap.go

var (
	latencyHist = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "app",
		Subsystem: "eth2",
		Name:      "latency_seconds",
		Help:      "Latency in seconds for eth2 beacon node requests",
	}, []string{"endpoint"})

	errorCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "app",
		Subsystem: "eth2",
		Name:      "errors_total",
		Help:      "Total number of errors returned by eth2 beacon node requests",
	}, []string{"endpoint"})
)

// NewHTTPService returns a new instrumented eth2 http service.
func NewHTTPService(ctx context.Context, params ...eth2http.Parameter) (*Service, error) {
	eth2Svc, err := eth2http.New(ctx, params...)
	if err != nil {
		return nil, errors.Wrap(err, "new eth2http")
	}

	eth2Cl, ok := eth2Svc.(*eth2http.Service)
	if !ok {
		return nil, errors.New("invalid eth2http service")
	}

	return &Service{Service: eth2Cl}, nil
}

// Service wraps an eth2http.Service adding prometheus metrics and error wrapping.
type Service struct {
	*eth2http.Service
}

// latency measures endpoint latency.
// Usage:
//  defer latency("endpoint")()
func latency(endpoint string) func() {
	t0 := time.Now()
	return func() {
		latencyHist.WithLabelValues(endpoint).Observe(time.Since(t0).Seconds())
	}
}

// incError increments the error counter.
func incError(endpoint string) {
	errorCount.WithLabelValues(endpoint).Inc()
}
