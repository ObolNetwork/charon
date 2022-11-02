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
	"net"
	"net/url"
	"time"

	eth2http "github.com/attestantio/go-eth2-client/http"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/forkjoin"
	"github.com/obolnetwork/charon/app/promauto"
	"github.com/obolnetwork/charon/app/z"
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
	_ Client = (*httpAdapter)(nil)
	_ Client = multi{}
)

// Instrument returns a new multi instrumented client using the provided clients as backends.
func Instrument(clients ...Client) (Client, error) {
	if len(clients) == 0 {
		return nil, errors.New("clients empty")
	}

	return multi{clients: clients}, nil
}

// AdaptEth2HTTP returns a Client wrapping an eth2http service by adding experimental endpoints.
// Note that the returned client doesn't wrap errors, so they are unstructured without stacktraces.
func AdaptEth2HTTP(eth2Svc *eth2http.Service, timeout time.Duration) Client {
	return httpAdapter{Service: eth2Svc, timeout: timeout}
}

// NewMultiHTTP returns a new instrumented multi eth2 http client.
func NewMultiHTTP(ctx context.Context, timeout time.Duration, addresses ...string) (Client, error) {
	var clients []Client
	for _, address := range addresses {
		eth2Svc, err := eth2http.New(ctx,
			eth2http.WithLogLevel(zeroLogInfo),
			eth2http.WithAddress(address),
			eth2http.WithTimeout(timeout),
		)
		if err != nil {
			return nil, wrapError(ctx, err, "new eth2 client")
		}
		eth2Http, ok := eth2Svc.(*eth2http.Service)
		if !ok {
			return nil, errors.New("invalid eth2 http service")
		}

		clients = append(clients, AdaptEth2HTTP(eth2Http, timeout))
	}

	return Instrument(clients...)
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

func (m multi) AggregateBeaconCommitteeSelections(ctx context.Context, selections []*eth2exp.BeaconCommitteeSelection) ([]*eth2exp.BeaconCommitteeSelection, error) {
	const label = "aggregate_beacon_committee_selections"

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) ([]*eth2exp.BeaconCommitteeSelection, error) {
			return cl.AggregateBeaconCommitteeSelections(ctx, selections)
		},
		nil,
	)
	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

func (m multi) AggregateSyncCommitteeSelections(ctx context.Context, selections []*eth2exp.SyncCommitteeSelection) ([]*eth2exp.SyncCommitteeSelection, error) {
	const label = "aggregate_sync_committee_selections"

	res, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) ([]*eth2exp.SyncCommitteeSelection, error) {
			return cl.AggregateSyncCommitteeSelections(ctx, selections)
		},
		nil,
	)
	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res, err
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
		nokResp    forkjoin.Result[Client, O]
		hasNokResp bool
		zero       O
	)
	for res := range join() {
		if ctx.Err() != nil {
			return zero, ctx.Err()
		} else if res.Err == nil && isSuccess(res.Output) {
			return res.Output, nil
		} else {
			nokResp = res
			hasNokResp = true
		}
	}

	if ctx.Err() != nil {
		return zero, ctx.Err()
	} else if !hasNokResp {
		return zero, errors.New("bug: no forkjoin results")
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

// wrapError returns the error as a wrapped structured error.
func wrapError(ctx context.Context, err error, label string) error {
	// Decompose go-eth2-client http errors
	if e2err := new(eth2http.Error); errors.As(err, e2err) {
		err = errors.New("nok http response",
			z.Int("status_code", e2err.StatusCode),
			z.Str("endpoint", e2err.Endpoint),
			z.Str("method", e2err.Method),
			z.Str("data", string(e2err.Data)),
		)
	}

	// Decompose url errors
	if uerr := new(url.Error); errors.As(err, &uerr) {
		msg := "http request aborted" // The request didn't complete, no http response
		if ctx.Err() != nil {
			msg = "caller cancelled http request"
		} else if errors.Is(uerr.Err, context.DeadlineExceeded) || errors.Is(uerr.Err, context.Canceled) {
			msg = "http request timeout"
		}
		err = errors.Wrap(uerr.Err, msg,
			z.Str("url", uerr.URL),
			z.Str("method", uerr.Op),
		)
	}

	// Decompose net errors
	if nerr := new(net.OpError); errors.As(err, &nerr) {
		msg := "network operation error: " + nerr.Op
		if ctx.Err() != nil {
			msg = "caller cancelled network operation: " + nerr.Op
		} else if errors.Is(nerr.Err, context.DeadlineExceeded) || errors.Is(nerr.Err, context.Canceled) {
			msg = "network operation timeout: " + nerr.Op
		}
		err = errors.Wrap(nerr.Err, msg, z.Any("address", nerr.Addr))
	}

	return errors.Wrap(err, "beacon api "+label, z.Str("label", label))
}
