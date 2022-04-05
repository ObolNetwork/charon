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

// Package retry provides a generic async slot function executor with retries for robustness against network failures.
// Functions are linked to a slot, executed asynchronously and network or context errors retried with backoff
// until duties related to a slot have elapsed (5 slots later).
package retry

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/tracer"
	"github.com/obolnetwork/charon/app/z"
)

// lateFactor defines the number of slots duties may be late.
// See https://pintail.xyz/posts/modelling-the-impact-of-altair/#proposer-and-delay-rewards.
const lateFactor = 5

// slotTimeProvider defines eth2client interface for resolving slot start times.
type slotTimeProvider interface {
	eth2client.GenesisTimeProvider
	eth2client.SlotDurationProvider
}

// New returns a new Retryer instance.
func New(ctx context.Context, eth2Svc eth2client.Service) (*Retryer, error) {
	eth2Cl, ok := eth2Svc.(slotTimeProvider)
	if !ok {
		return nil, errors.New("invalid eth2 service")
	}

	genesis, err := eth2Cl.GenesisTime(ctx)
	if err != nil {
		return nil, err
	}

	duration, err := eth2Cl.SlotDuration(ctx)
	if err != nil {
		return nil, err
	}

	// deadlineFunc returns the time after which duties for a slot have elapsed.
	deadlineFunc := func(slot int64) time.Time {
		start := genesis.Add(duration * time.Duration(slot))
		return start.Add(duration * time.Duration(lateFactor))
	}

	// backoffProvider is a naive constant 1s backoff function.
	backoffProvider := func() func() <-chan time.Time {
		return func() <-chan time.Time {
			const backoff = time.Second
			return time.After(backoff)
		}
	}

	return &Retryer{
		shutdown:        make(chan struct{}),
		deadlineFunc:    deadlineFunc,
		backoffProvider: backoffProvider,
	}, nil
}

// Retryer provides execution of functions asynchronously with retry adding robustness to network errors.
type Retryer struct {
	shutdown        chan struct{}
	deadlineFunc    func(slot int64) time.Time
	backoffProvider func() func() <-chan time.Time

	wg sync.WaitGroup
}

// DoAsync will execute the function including retries on network or context errors.
// It is intended to be used asynchronously:
//   go retryer.DoAsync(ctx, duty.Slot, "foo", fn)
func (r *Retryer) DoAsync(parent context.Context, slot int64, name string, fn func(context.Context) error) {
	if r.isShutdown() {
		return
	}

	r.wg.Add(1)
	defer r.wg.Done()

	deadline := r.deadlineFunc(slot)
	backoffFunc := r.backoffProvider()

	// Switch to a new context since this is async and parent context may be closed.
	ctx := log.CopyFields(context.Background(), parent)
	ctx = log.WithTopic(ctx, "retry")
	ctx = trace.ContextWithSpan(ctx, trace.SpanFromContext(parent))
	ctx, cancel := context.WithDeadline(ctx, deadline)
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
			log.Warn(ctx, "Temporary failure (will retry) calling "+name, z.Err(err))
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

// isTemporaryBeaconErr returns true if the error is a temporary beacon node error.
// eth2http doesn't return structured errors or error sentinels, so this is brittle.
func isTemporaryBeaconErr(err error) bool {
	// Check for timing errors like:
	//  - Proposer duties were requested for a future epoch.
	//  - Cannot create attestation for future slot.
	if strings.Contains(err.Error(), "future") { //nolint:gosimple // More checks will be added below.
		return true
	}

	// TODO(corver): Add more checks here.

	return false
}

// isShutdown returns true if Shutdown has been called.
func (r *Retryer) isShutdown() bool {
	select {
	case <-r.shutdown:
		return true
	default:
		return false
	}
}

// Shutdown triggers graceful shutdown and waits for all active function to complete or timeout.
func (r *Retryer) Shutdown(ctx context.Context) {
	close(r.shutdown)

	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		done <- struct{}{}
	}()

	select {
	case <-ctx.Done():
	case <-done:
	}
}
