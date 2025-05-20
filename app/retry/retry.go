// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package retry provides a generic async function executor with retries for robustness against network failures.
// Functions are linked to a deadline, executed asynchronously and network or context errors retried with backoff
// until the deadline has elapsed.
package retry

import (
	"context"
	"fmt"
	"net"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/expbackoff"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/tracer"
	"github.com/obolnetwork/charon/app/z"
)

// Derived from expbackoff.DefaultConfig, but MaxDelay is 12s.
var backoffConfig = expbackoff.Config{
	BaseDelay:  250 * time.Millisecond,
	Multiplier: 1.6,
	Jitter:     0.1,
	MaxDelay:   12 * time.Second,
}

// New returns a new Retryer instance.
func New[T any](timeoutFunc func(T) (time.Time, bool)) *Retryer[T] {
	// ctxTimeoutFunc returns a context that is cancelled when duties for a slot have elapsed.
	ctxTimeoutFunc := func(ctx context.Context, t T) (context.Context, context.CancelFunc) {
		timeout, ok := timeoutFunc(t)
		if !ok {
			return ctx, func() {}
		}

		return context.WithDeadline(ctx, timeout)
	}

	backoffProvider := func() func(int) <-chan time.Time {
		return func(iteration int) <-chan time.Time {
			delay := delayForIteration(iteration)
			return time.After(delay)
		}
	}

	return newInternal(ctxTimeoutFunc, backoffProvider)
}

// NewForT returns a new Retryer instance for testing supporting a custom clock.
func NewForT[T any](
	_ *testing.T,
	ctxTimeoutFunc func(context.Context, T) (context.Context, context.CancelFunc),
	backoffProvider func() func(int) <-chan time.Time,
) *Retryer[T] {
	return newInternal(ctxTimeoutFunc, backoffProvider)
}

// delayForIteration returns the delay for the given iteration:
// 250ms, 400ms, 640ms, 1s, 1.6s, 2.56s, 4.096s, 6.5536s, 10.48576s, 12s
func delayForIteration(iteration int) time.Duration {
	return expbackoff.Backoff(backoffConfig, iteration)
}

func newInternal[T any](
	ctxTimeoutFunc func(context.Context, T) (context.Context, context.CancelFunc),
	backoffProvider func() func(int) <-chan time.Time,
) *Retryer[T] {
	// Create a fresh context used as parent of all async contexts
	ctx, cancel := context.WithCancel(context.Background())

	return &Retryer[T]{
		asyncCtx:        ctx,
		asyncCancel:     cancel,
		shutdown:        make(chan struct{}),
		ctxTimeoutFunc:  ctxTimeoutFunc,
		backoffProvider: backoffProvider,
		active:          make(map[string]int),
	}
}

// Retryer provides execution of functions asynchronously with retry adding robustness to network errors.
// The generic type T abstracts the deadline argument.
type Retryer[T any] struct {
	asyncCtx        context.Context
	asyncCancel     context.CancelFunc
	ctxTimeoutFunc  func(context.Context, T) (context.Context, context.CancelFunc)
	backoffProvider func() func(int) <-chan time.Time

	mu       sync.Mutex
	shutdown chan struct{}
	active   map[string]int // Active keeps track of active DoAsyncs.
}

// DoAsync will execute the function including retries on network or context errors.
// It is intended to be used asynchronously:
//
//	go retryer.DoAsync(ctx, duty, "foo", fn)
func (r *Retryer[T]) DoAsync(parent context.Context, t T, topic, name string, fn func(context.Context) error) {
	label := path.Join(topic, name)

	if !r.startAsync(label) {
		return
	}
	defer r.endAsync(label)

	backoffFunc := r.backoffProvider()

	// Switch to the async context since parent context may be closed soon.
	ctx := log.CopyFields(r.asyncCtx, parent)                       // Copy log fields to new context
	ctx = trace.ContextWithSpan(ctx, trace.SpanFromContext(parent)) // Copy tracing span to new context
	ctx = log.WithTopic(ctx, topic)
	ctx, cancel := r.ctxTimeoutFunc(ctx, t)
	defer cancel()

	_, span := tracer.Start(r.asyncCtx, "app/retry.DoAsync")
	span.SetAttributes(attribute.String("topic", topic))
	span.SetAttributes(attribute.String("name", name))
	defer span.End()

	for i := 0; ; i++ {
		span.AddEvent("retry.attempt.start", trace.WithAttributes(attribute.Int("i", i)))

		err := fn(ctx)
		if err == nil {
			span.SetStatus(codes.Ok, "success")
			return
		}

		var nerr net.Error
		isNetErr := errors.As(err, &nerr)
		isTempErr := isTemporaryBeaconErr(err)
		isCtxErr := errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
		// Note that the local context is not checked, since we care about downstream timeouts.

		if !isCtxErr && !isNetErr && !isTempErr {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			log.Error(ctx, "Permanent failure calling "+label, err)

			return
		}

		if ctx.Err() == nil {
			log.Warn(ctx, "Temporary failure (will retry) calling "+label, err)
			select {
			case <-backoffFunc(i):
			case <-ctx.Done():
			case <-r.shutdown:
				return
			}
		}

		if r.asyncCtx.Err() != nil {
			return // Shutdown, return without logging
		} else if ctx.Err() != nil {
			span.SetStatus(codes.Error, "timeout")
			// No need to log this at error level since tracker will analyse and report on failed duties.
			log.Debug(ctx, "Timeout calling "+label+", duty expired")

			return
		}
	}
}

// startAsync marks an async action of name as active.
func (r *Retryer[T]) startAsync(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isShutdown() {
		return false
	}

	r.active[name]++

	return true
}

// endAsync marks an async action of name as complete.
func (r *Retryer[T]) endAsync(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.active[name]--
	if r.active[name] == 0 {
		delete(r.active, name)
	}
}

// someActive returns true if some async actions are active.
func (r *Retryer[T]) someActive() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.active) > 0
}

// fmtActive returns a human-readable string of the active async.
func (r *Retryer[T]) fmtActive() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return fmt.Sprint(r.active)
}

// isShutdown returns true if Shutdown has been called.
func (r *Retryer[T]) isShutdown() bool {
	select {
	case <-r.shutdown:
		return true
	default:
		return false
	}
}

// Shutdown triggers graceful shutdown and waits for all active function to complete or timeout.
func (r *Retryer[T]) Shutdown(ctx context.Context) {
	r.mu.Lock() // Prevent new asyncs from starting while close the shutdown channel.
	close(r.shutdown)
	r.mu.Unlock()

	r.asyncCancel()

	checkDoneTicker := time.NewTicker(100 * time.Millisecond)
	defer checkDoneTicker.Stop()

	for r.someActive() {
		select {
		case <-ctx.Done():
			log.Error(ctx, "Retryer shutdown timeout waiting for active asyncs to complete", nil, z.Str("active", r.fmtActive()))
		case <-checkDoneTicker.C:
		}
	}
}

// isTemporaryBeaconErr returns true if the error is a temporary beacon node error.
// eth2http doesn't return structured errors or error sentinels, so this is brittle.
func isTemporaryBeaconErr(err error) bool {
	// Check for timing errors like:
	//  - Proposer duties were requested for a future epoch.
	//  - Cannot create attestation for future slot.
	if strings.Contains(err.Error(), "future") {
		return true
	}

	// More timing issues:
	//  - Attestations must be from the current or previous epoch
	if strings.Contains(err.Error(), "current or previous") {
		return true
	}

	if strings.Contains(err.Error(), "retryable") {
		return true
	}

	return false
}
