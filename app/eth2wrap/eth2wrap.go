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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/forkjoin"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
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
	_ Client = (*httpWrap)(nil)
	_ Client = multi{}
)

// Wrap returns a new multi instrumented client wrapping the provided eth2 services.
func Wrap(eth2Svcs ...eth2client.Service) (Client, error) {
	if len(eth2Svcs) == 0 {
		return nil, errors.New("eth2 services empty")
	}
	var clients []Client
	for _, eth2Svc := range eth2Svcs {
		cl, ok := eth2Svc.(Client)
		if !ok {
			return nil, errors.New("invalid eth2 service")
		}
		clients = append(clients, cl)
	}

	return multi{clients: clients}, nil
}

// NewMultiHTTP returns a new instrumented multi eth2 http client.
func NewMultiHTTP(ctx context.Context, timeout time.Duration, addresses ...string) (Client, error) {
	var eth2Svcs []eth2client.Service
	for _, address := range addresses {
		eth2Svc, err := eth2http.New(ctx,
			eth2http.WithLogLevel(zeroLogInfo),
			eth2http.WithAddress(address),
			eth2http.WithTimeout(timeout),
		)
		if err != nil {
			return nil, errors.Wrap(err, "new eth2 client")
		}

		// Append wrapped eth2http which contains all the experimental methods from eth2util/eth2exp.
		eth2Svcs = append(eth2Svcs, httpWrap{eth2Svc.(*eth2http.Service)})
	}

	return Wrap(eth2Svcs...)
}

// multi implements Client by wrapping multiple clients, calling them in parallel
// and returning the first successful response.
// It also adds prometheus metrics and error wrapping.
type multi struct {
	clients []Client
}

func (multi) Name() string {
	return "eth2wrap.multi"
}

func (m multi) Address() string {
	// TODO(corver): return "best" address.
	return m.clients[0].Address()
}

func NewWrapHTTP(eth2Svc eth2client.Service) (Client, error) {
	httpCl, ok := eth2Svc.(*eth2http.Service)
	if !ok {
		return nil, errors.New("invalid eth2http client")
	}

	return httpWrap{httpCl}, nil
}

// httpWrap implements Client by wrapping eth2http.Service,
// also implements experimental interfaces which are absent in eth2http.Service.
type httpWrap struct {
	*eth2http.Service
}

// SubmitBeaconCommitteeSubscriptions implements eth2exp.BeaconCommitteeSubscriptionsSubmitter.
// TODO(dhruv): Implement this method when there's need to connect to external beacon node.
func (httpWrap) SubmitBeaconCommitteeSubscriptions(context.Context, []*eth2exp.BeaconCommitteeSubscription) ([]eth2exp.BeaconCommitteeSubscriptionResponse, error) {
	return nil, nil
}

// provide calls the work function with each client in parallel, returning the
// first successful result or first error.
func provide[O any](ctx context.Context, clients []Client,
	work forkjoin.Work[Client, O], isSuccess func(O) bool,
) (O, error) {
	if isSuccess == nil {
		isSuccess = func(O) bool { return true }
	}

	fork, join, cancel := forkjoin.New(ctx, work,
		forkjoin.WithoutFailFast(),
		forkjoin.WithWorkers(len(clients)),
	)
	for _, client := range clients {
		fork(client)
	}
	defer cancel()

	var (
		nokResp forkjoin.Result[Client, O]
		zero    O
	)
	for res := range join() {
		if ctx.Err() != nil {
			return zero, ctx.Err()
		} else if res.Err == nil && isSuccess(res.Output) {
			return res.Output, nil
		} else {
			nokResp = res
		}
	}

	return nokResp.Output, nokResp.Err
}

type empty struct{}

// submit proxies provide, but returns nil instead of a successful result.
func submit(ctx context.Context, clients []Client, work func(context.Context, Client) error) error {
	_, err := provide(ctx, clients,
		func(ctx context.Context, cl Client) (empty, error) {
			return empty{}, work(ctx, cl)
		},
		nil,
	)

	return err
}

// latency measures endpoint latency.
// Usage:
//
//	defer latency("endpoint")()
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
