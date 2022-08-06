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

// Package forkjoin provides an API for "doing work
// concurrently (fork) and then waiting for the results (join)".
package forkjoin

import (
	"context"
	"sync"

	"github.com/obolnetwork/charon/app/errors"
)

const (
	defaultWorkers  = 8
	failFastEnabled = false
)

// Fork enqueues the input to be processed asynchronously.
// Note Fork will panic if called after Join.
type Fork[I any] func(I)

// Join closes the input queue and returns the result channel.
// Note Fork will panic if called after Join.
// Note Join must only be called once, otherwise panics.
type Join[O any] func() Results[O]

// Work defines the function workers will call. It accepts input and returns output types.
type Work[I, O any] func(context.Context, I) (O, error)

// Results contains enqueued result outputs.
type Results[O any] <-chan Result[O]

// Result is output of the work function.
type Result[O any] struct {
	Result O
	Err    error
}

// Flatten blocks and returns all the outputs when all completed and
// either the first non-context-cancelled error or context-cancelled
// if all errors are context cancelled (to return real failure reason).
func (r Results[O]) Flatten() ([]O, error) {
	var (
		ctxErr   error
		otherErr error
		resp     []O
	)
	for result := range r {
		resp = append(resp, result.Result)

		if result.Err == nil {
			continue
		}

		if errors.Is(result.Err, context.Canceled) && ctxErr == nil {
			ctxErr = result.Err
		}
		if !errors.Is(result.Err, context.Canceled) && otherErr == nil {
			otherErr = result.Err
		}
	}

	if otherErr != nil {
		return resp, otherErr
	} else if ctxErr != nil {
		return resp, ctxErr
	}

	return resp, nil
}

type options struct {
	w        int
	failFast bool
}

type Option func(*options)

// WithWorkers returns an option configuring the forkjoin with w number of workers.
func WithWorkers(w int) Option {
	return func(o *options) {
		o.w = w
	}
}

// WithFailFast stops execution on any error. Active work function contexts are cancelled
// and no further inputs are executed.
func WithFailFast() Option {
	return func(o *options) {
		o.failFast = true
	}
}

// New returns a new forkjoin instance with generic input type I and output type O.
// It provides a pattern for "doing work concurrently (fork) and then waiting for the results (join)".
//
// Usage:
//   var workFunc := func(ctx context.Context, input MyInput) (MyResult, error) {
//     ... do work
//     return result, nil
//   }
//
//   fork, join := forkjoin.New[MyInput,MyResult](ctx, workFunc)
//   for _, in := range inputs {
//     fork(in) // Note that calling fork AFTER join panics!
//   }
//
//   resultChan := join()
//   // Either read results from the channel as they appear
//   for result := range resultChan { ... }
//   // Or block until all results are complete and flatten
//   results, firstErr := resultChan.Flatten()
//
func New[I, O any](ctx context.Context, work Work[I, O], opts ...Option) (Fork[I], Join[O]) {
	options := options{
		w:        defaultWorkers,
		failFast: failFastEnabled,
	}

	for _, opt := range opts {
		opt(&options)
	}

	var (
		wg      sync.WaitGroup
		zero    O
		input   = make(chan I)
		results = make(chan Result[O])
	)

	// enqueue output asynchronously since results channel is unbuffered/blocking.
	enqueueOut := func(o O, err error) {
		go func() {
			results <- Result[O]{Result: o, Err: err}
			wg.Done()
		}()
	}

	ctx, cancel := context.WithCancel(ctx)

	for i := 0; i < options.w; i++ { // Start workers
		go func() {
			for in := range input { // Process all inputs (channel closed on Join)
				if ctx.Err() != nil { // Skip work if failed fast
					enqueueOut(zero, ctx.Err())
					continue
				}

				out, err := work(ctx, in)
				if options.failFast && err != nil { // Maybe fail fast
					cancel()
				}

				enqueueOut(out, err)
			}
		}()
	}

	// Fork enqueues inputs, keeping track of how many was enqueued.
	fork := func(i I) {
		wg.Add(1)
		input <- i
	}

	// Join returns the results channel that will contain all the results in the future.
	// It also closes the input queue (causing subsequent calls Fork to panic)
	// It also starts a shutdown goroutine that closes the results channel when processing completed
	join := func() Results[O] {
		close(input)

		go func() {
			// Cleanup when done
			wg.Wait()
			close(results)
			cancel()
		}()

		return results
	}

	return fork, join
}
