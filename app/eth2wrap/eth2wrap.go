// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package eth2wrap provides a wrapper for eth2http.Service adding prometheus metrics and error wrapping.
package eth2wrap

import (
	"context"
	"net"
	"net/url"
	"sync"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2http "github.com/attestantio/go-eth2-client/http"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/forkjoin"
	"github.com/obolnetwork/charon/app/promauto"
	"github.com/obolnetwork/charon/app/z"
)

//go:generate go run genwrap/genwrap.go

const (
	zeroLogInfo = 1           // Avoid importing zero log for this constant.
	bestPeriod  = time.Minute // Best client selector period.
)

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
	_ Client = (*lazy)(nil)
)

// Instrument returns a new multi instrumented client using the provided clients as backends.
func Instrument(clients ...Client) (Client, error) {
	if len(clients) == 0 {
		return nil, errors.New("clients empty")
	}

	return newMulti(clients), nil
}

// WithSyntheticDuties wraps the provided client adding synthetic duties.
func WithSyntheticDuties(cl Client) Client {
	return &synthWrapper{
		Client:             cl,
		synthProposerCache: newSynthProposerCache(),
		feeRecipients:      make(map[eth2p0.ValidatorIndex]bellatrix.ExecutionAddress),
	}
}

// NewMultiHTTP returns a new instrumented multi eth2 http client.
func NewMultiHTTP(timeout time.Duration, addresses ...string) (Client, error) {
	var clients []Client
	for _, address := range addresses {
		address := address // Capture range variable.

		parameters := []eth2http.Parameter{
			eth2http.WithLogLevel(zeroLogInfo),
			eth2http.WithAddress(address),
			eth2http.WithTimeout(timeout),
			eth2http.WithAllowDelayedStart(true),
			eth2http.WithEnforceJSON(featureset.Enabled(featureset.JSONRequests)),
		}

		cl := newLazy(func(ctx context.Context) (Client, error) {
			eth2Svc, err := eth2http.New(ctx, parameters...)
			if err != nil {
				return nil, wrapError(ctx, err, "new eth2 client", z.Str("address", address))
			}
			eth2Http, ok := eth2Svc.(*eth2http.Service)
			if !ok {
				return nil, errors.New("invalid eth2 http service")
			}

			return AdaptEth2HTTP(eth2Http, timeout), nil
		})

		clients = append(clients, cl)
	}

	return Instrument(clients...)
}

// provide calls the work function with each client in parallel, returning the
// first successful result or first error.
// The bestIdxFunc is called with the index of the client returning a successful response.
func provide[O any](ctx context.Context, clients []Client,
	work forkjoin.Work[Client, O], isSuccessFunc func(O) bool, bestSelector *bestSelector,
) (O, error) {
	if isSuccessFunc == nil {
		isSuccessFunc = func(O) bool { return true }
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
		} else if res.Err == nil && isSuccessFunc(res.Output) {
			if bestSelector != nil {
				bestSelector.Increment(res.Input.Address())
			}

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
func submit(ctx context.Context, clients []Client, work func(context.Context, Client) error, selector *bestSelector) error {
	_, err := provide(ctx, clients,
		func(ctx context.Context, cl Client) (empty, error) {
			return empty{}, work(ctx, cl)
		},
		nil, selector,
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
func wrapError(ctx context.Context, err error, label string, fields ...z.Field) error {
	// Decompose go-eth2-client http errors
	if apiErr := new(eth2api.Error); errors.As(err, &apiErr) {
		err = errors.New("nok http response",
			z.Int("status_code", apiErr.StatusCode),
			z.Str("endpoint", apiErr.Endpoint),
			z.Str("method", apiErr.Method),
			z.Str("data", string(apiErr.Data)),
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

	return errors.Wrap(err, "beacon api "+label, append(fields, z.Str("label", label))...)
}

// newBestSelector returns a new bestSelector.
func newBestSelector(period time.Duration) *bestSelector {
	return &bestSelector{
		counts: make(map[string]int),
		start:  time.Now(),
		period: period,
	}
}

// bestSelector calculates the "best client index" per period.
type bestSelector struct {
	mu     sync.RWMutex
	counts map[string]int
	start  time.Time
	period time.Duration
}

// BestAddress returns the best client address when ok is true.
func (s *bestSelector) BestAddress() (address string, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var maxCount int
	for addr, count := range s.counts {
		if count > maxCount {
			ok = true
			address = addr
			maxCount = count
		}
	}

	return address, ok
}

// Increment increments the counter for the given address.
func (s *bestSelector) Increment(address string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if time.Since(s.start) > s.period { // Reset counters after period.
		s.counts = make(map[string]int)
		s.start = time.Now()
	}

	s.counts[address]++
}
