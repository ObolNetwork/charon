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

	eth2client "github.com/attestantio/go-eth2-client"
	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2multi "github.com/attestantio/go-eth2-client/multi"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/obolnetwork/charon/app/errors"
)

//go:generate go run genwrap/genwrap.go

const zeroLogInfo = 1 // Avoid importing zero log for this constant.

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

	// Interface assertions.
	_ eth2Provider = (*eth2http.Service)(nil)
	_ eth2Provider = (*eth2multi.Service)(nil)
)

// Wrap returns an instrumented wrapped eth2 service.
func Wrap(eth2Svc eth2client.Service) (*Service, error) {
	eth2Cl, ok := eth2Svc.(eth2Provider)
	if !ok {
		return nil, errors.New("invalid eth2 service")
	}

	return &Service{eth2Provider: eth2Cl}, nil
}

// NewHTTPService returns a new instrumented eth2 http service.
func NewHTTPService(ctx context.Context, timeout time.Duration, addresses ...string) (*Service, error) {
	var (
		eth2Svc eth2client.Service
		err     error
	)
	if len(addresses) == 0 {
		return nil, errors.New("no addresses")
	} else if len(addresses) == 1 {
		eth2Svc, err = eth2http.New(ctx,
			eth2http.WithLogLevel(zeroLogInfo),
			eth2http.WithAddress(addresses[0]),
			eth2http.WithTimeout(timeout),
		)
	} else {
		eth2Svc, err = eth2multi.New(ctx,
			eth2multi.WithLogLevel(zeroLogInfo),
			eth2multi.WithMonitor(eth2Monitor{}),
			eth2multi.WithAddresses(addresses),
			eth2multi.WithTimeout(timeout),
		)
	}
	if err != nil {
		return nil, errors.Wrap(err, "new eth2 client")
	}

	eth2Cl, ok := eth2Svc.(eth2Provider)
	if !ok {
		return nil, errors.New("invalid eth2 service")
	}

	return &Service{eth2Provider: eth2Cl}, nil
}

// Service wraps an eth2Provider adding prometheus metrics and error wrapping.
type Service struct {
	eth2Provider
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

// eth2Monitor implements eth2metrics.Monitor enabling eth2multi prometheus metrics.
type eth2Monitor struct{}

func (eth2Monitor) Presenter() string {
	return "prometheus"
}
