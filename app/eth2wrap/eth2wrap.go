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
	"github.com/obolnetwork/charon/app/log"
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

	usingFallbackGauge = promauto.NewGauge(prometheus.GaugeOpts{
        Namespace: "app",
        Subsystem: "eth2",
        Name:      "using_fallback",
        Help:      "Indicates if client is using fallback (1) or primary (0) beacon node",
    })

	// Interface assertions.
	_ Client = (*httpAdapter)(nil)
	_ Client = multi{}
	_ Client = (*lazy)(nil)
)

// Instrument returns a new multi instrumented client using the provided clients as backends
// and fallback as alternatives when all clients fail.
func Instrument(clients []Client, fallback []Client) (Client, error) {
	if len(clients) == 0 {
		return nil, errors.New("clients empty")
	}

	return newMulti(clients, fallback), nil
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
func NewMultiHTTP(timeout time.Duration, forkVersion [4]byte, headers map[string]string, addrs []string, fallbackAddrs []string) (Client, error) {
	return Instrument(
		newClients(timeout, forkVersion, headers, addrs),
		newClients(timeout, forkVersion, headers, fallbackAddrs),
	)
}

// NewSimnetFallbacks returns a slice of Client initialized with the provided settings. Used in Simnet setting.
func NewSimnetFallbacks(timeout time.Duration, forkVersion [4]byte, headers map[string]string, addresses []string) []Client {
	var clients []Client
	for _, address := range addresses {
		clients = append(clients, newBeaconClient(timeout, forkVersion, headers, address))
	}

	return clients
}

// newClients returns a slice of Client initialized with the provided settings.
func newClients(timeout time.Duration, forkVersion [4]byte, headers map[string]string, addresses []string) []Client {
	var clients []Client
	for _, address := range addresses {
		clients = append(clients, newBeaconClient(timeout, forkVersion, headers, address))
	}

	return clients
}

// newBeaconClient returns a Client with the provided settings.
func newBeaconClient(timeout time.Duration, forkVersion [4]byte, headers map[string]string, address string) Client {
	parameters := []eth2http.Parameter{
		eth2http.WithLogLevel(zeroLogInfo),
		eth2http.WithAddress(address),
		eth2http.WithTimeout(timeout),
		eth2http.WithAllowDelayedStart(true),
		eth2http.WithEnforceJSON(featureset.Enabled(featureset.JSONRequests)),
		eth2http.WithExtraHeaders(headers),
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

		adaptedCl := AdaptEth2HTTP(eth2Http, headers, timeout)
		adaptedCl.SetForkVersion(forkVersion)

		return adaptedCl, nil
	})

	return cl
}

type provideArgs struct {
	client Client
}

// provide calls the work function with each client in parallel, returning the
// first successful result or first error.
// The bestIdxFunc is called with the index of the client returning a successful response.
func provide[O any](ctx context.Context, clients []Client, fallbacks []Client,
	work forkjoin.Work[provideArgs, O], isSuccessFunc func(O) bool, bestSelector *bestSelector,
) (O, error) {
	if isSuccessFunc == nil {
		isSuccessFunc = func(O) bool { return true }
	}

	zero := func() O { var z O; return z }()

	runForkJoin := func(clients []Client, isFallback bool) (O, error) {

		if isFallback {
            usingFallbackGauge.Set(1)
        } else {
            usingFallbackGauge.Set(0)
        }

		fork, join, cancel := forkjoin.New(ctx, work,
			forkjoin.WithoutFailFast(),
			forkjoin.WithWorkers(len(clients)),
		)
		defer cancel()

		for _, client := range clients {
			fork(provideArgs{client: client})
		}

		var (
			nokResp    forkjoin.Result[provideArgs, O]
			hasNokResp bool
		)
		for res := range join() {
			if ctx.Err() != nil {
				return zero, ctx.Err()
			} else if res.Err == nil && isSuccessFunc(res.Output) {
				if bestSelector != nil {
					bestSelector.Increment(res.Input.client.Address())
				}

				return res.Output, nil
			}

			nokResp = res
			hasNokResp = true
		}

		if ctx.Err() != nil {
			return zero, ctx.Err()
		} else if !hasNokResp {
			return zero, errors.New("bug: no forkjoin results")
		}

		return nokResp.Output, nokResp.Err
	}

	output, err := runForkJoin(clients, false)
	if err == nil || ctx.Err() != nil || len(fallbacks) == 0 {
		return output, err
	}

	return runForkJoin(fallbacks, true)
}

type empty struct{}

// submit proxies provide, but returns nil instead of a successful result.
func submit(ctx context.Context, clients []Client, fallbacks []Client, work func(context.Context, provideArgs) error, selector *bestSelector) error {
	_, err := provide(ctx, clients, fallbacks,
		func(ctx context.Context, args provideArgs) (empty, error) {
			return empty{}, work(ctx, args)
		},
		nil, selector,
	)

	return err
}

// latency measures endpoint latency and writes metrics and logs results.
// Usage:
//
//	defer latency("endpoint")()
func latency(ctx context.Context, endpoint string, enableLogs bool) func() {
	if enableLogs {
		log.Debug(ctx, "Calling beacon node endpoint...", z.Str("endpoint", endpoint))
	}
	t0 := time.Now()

	return func() {
		rtt := time.Since(t0)
		latencyHist.WithLabelValues(endpoint).Observe(rtt.Seconds())
		if enableLogs {
			log.Debug(ctx, "Beacon node call finished", z.Str("endpoint", endpoint))
		}
		// If BN call took more than 1 second, send WARN log
		if rtt > time.Second {
			log.Warn(ctx, "Beacon node call took longer than expected", nil, z.Str("endpoint", endpoint), z.Str("rtt", rtt.String()))
		}
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
