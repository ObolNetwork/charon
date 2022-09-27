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

// Package retry provides a generic async function executor with retries for robustness against network failures.
// Functions are linked to a deadline, executed asynchronously and network or context errors retried with backoff
// until the deadline has elapsed.
package retry

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/tracer"
	"github.com/obolnetwork/charon/app/z"
)

// New returns a new Retryer instance.
func New[T any](timeoutFunc func(T) (time.Time, bool)) (*Retryer[T], error) {
	// ctxTimeoutFunc returns a context that is cancelled when duties for a slot have elapsed.
	ctxTimeoutFunc := func(ctx context.Context, t T) (context.Context, context.CancelFunc) {
		timeout, ok := timeoutFunc(t)
		if !ok {
			return ctx, func() {}
		}

		ctx, cancel := context.WithDeadline(ctx, timeout)

		return errors.WithCtxErr(ctx, "duty expired"), cancel
	}

	// backoffProvider is a naive constant 1s backoff function.
	backoffProvider := func() func() <-chan time.Time {
		return func() <-chan time.Time {
			const backoff = time.Second
			return time.After(backoff)
		}
	}

	return &Retryer[T]{
		shutdown:        make(chan struct{}),
		ctxTimeoutFunc:  ctxTimeoutFunc,
		backoffProvider: backoffProvider,
		active:          make(map[string]int),
	}, nil
}

// NewForT returns a new Retryer instance for testing supporting a custom clock.
func NewForT[T any](
	_ *testing.T,
	ctxTimeoutFunc func(context.Context, T) (context.Context, context.CancelFunc),
	backoffProvider func() func() <-chan time.Time,
) (*Retryer[T], error) {
	return &Retryer[T]{
		shutdown:        make(chan struct{}),
		ctxTimeoutFunc:  ctxTimeoutFunc,
		backoffProvider: backoffProvider,
		active:          make(map[string]int),
	}, nil
}

// Retryer provides execution of functions asynchronously with retry adding robustness to network errors.
// The generic type T abstracts the deadline argument.
type Retryer[T any] struct {
	shutdown        chan struct{}
	ctxTimeoutFunc  func(context.Context, T) (context.Context, context.CancelFunc)
	backoffProvider func() func() <-chan time.Time

	wg sync.WaitGroup

	mu     sync.Mutex
	active map[string]int // Active keeps track of active DoAsyncs.
}

// DoAsync will execute the function including retries on network or context errors.
// It is intended to be used asynchronously:
//
//	go retryer.DoAsync(ctx, duty, "foo", fn)
func (r *Retryer[T]) DoAsync(parent context.Context, t T, name string, fn func(context.Context) error) {
	if r.isShutdown() {
		return
	}

	r.asyncStarted(name)
	defer r.asyncEnded(name)

	backoffFunc := r.backoffProvider()

	// Switch to a new context since this is async and parent context may be closed.
	ctx := log.CopyFields(context.Background(), parent)
	ctx = log.WithTopic(ctx, "retry")
	ctx = trace.ContextWithSpan(ctx, trace.SpanFromContext(parent))
	ctx, cancel := r.ctxTimeoutFunc(ctx, t)
	defer cancel()

	ctx, span := tracer.Start(ctx, "app/retry.DoAsync")
	defer span.End()
	span.SetAttributes(attribute.String("name", name))

	for i := 0; ; i++ {
		span.AddEvent("retry.attempt.start", trace.WithAttributes(attribute.Int("i", i)))

		err := fn(ctx)
		if err == nil {
			return
		}

		var nerr net.Error
		isNetErr := errors.As(err, &nerr)
		isTempErr := isTemporaryBeaconErr(err)
		isCtxErr := errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
		// Note that the local context is not checked, since we care about downstream timeouts.

		if !isCtxErr && !isNetErr && !isTempErr {
			log.Error(ctx, "Permanent failure calling "+name, err)
			return
		}

		if ctx.Err() == nil {
			log.Warn(ctx, "Temporary failure (will retry) calling "+name, err)
			span.AddEvent("retry.backoff.start")
			select {
			case <-backoffFunc():
			case <-ctx.Done():
			case <-r.shutdown:
				return
			}
			span.AddEvent("retry.backoff.done")
		}

		if ctx.Err() != nil {
			log.Error(ctx, "Timeout retrying "+name, ctx.Err())
			return
		}
	}
}

// asyncStarted marks an async action of name as active.
func (r *Retryer[T]) asyncStarted(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.wg.Add(1)
	r.active[name]++
}

// asyncEnded marks an async action of name as complete.
func (r *Retryer[T]) asyncEnded(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.active[name]--
	if r.active[name] == 0 {
		delete(r.active, name)
	}
	r.wg.Done()
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
	close(r.shutdown)

	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		log.Error(ctx, "Retryer shutdown timeout waiting for active asyncs to complete", nil, z.Str("active", r.fmtActive()))
	case <-done:
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

	// TODO(corver): Add more checks here.

	return false
}
