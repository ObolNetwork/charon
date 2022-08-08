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
	defaultInputBuf = 100
	defaultFailFast = true
)

// Fork function enqueues the input to be processed asynchronously.
// Note Fork may block temporarily while the input buffer is full, see WithInputBuffer.
// Note Fork will panic if called after Join.
type Fork[I any] func(I)

// Join function closes the input queue and returns the result channel.
// Note Fork will panic if called after Join.
// Note Join must only be called once, otherwise panics.
type Join[I, O any] func() Results[I, O]

// Work defines the work function signature workers will call.
type Work[I, O any] func(ctx context.Context, input I) (output O, err error)

// Results contains enqueued results.
type Results[I, O any] <-chan Result[I, O]

// Result contains the input and resulting output from the work function.
type Result[I, O any] struct {
	Input  I
	Output O
	Err    error
}

// Flatten blocks and returns all the outputs when all completed and
// the first "real error".
//
// A real error is the error that triggered the fail fast, all subsequent
// results will contain context cancelled errors.
func (r Results[I, O]) Flatten() ([]O, error) {
	var (
		ctxErr   error
		otherErr error
		resp     []O
	)
	for result := range r {
		resp = append(resp, result.Output)

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
	inputBuf int
	workers  int
	failFast bool
}

type Option func(*options)

// WithWorkers returns an option configuring a forkjoin with w number of workers.
func WithWorkers(w int) Option {
	return func(o *options) {
		o.workers = w
	}
}

// WithInputBuffer returns an option configuring a forkjoin with an input buffer of length i.
// Useful to prevent temporary blocking during calls to Fork.
func WithInputBuffer(i int) Option {
	return func(o *options) {
		o.inputBuf = i
	}
}

// WithoutFailFast returns an option configuring a forkjoin to not stop execution on any error.
func WithoutFailFast() Option {
	return func(o *options) {
		o.failFast = false
	}
}

// New returns a new forkjoin instance with generic input type I and output type O.
// It provides an API for "doing work concurrently (fork) and then waiting for the results (join)".
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
func New[I, O any](ctx context.Context, work Work[I, O], opts ...Option) (Fork[I], Join[I, O]) {
	options := options{
		workers:  defaultWorkers,
		inputBuf: defaultInputBuf,
		failFast: defaultFailFast,
	}

	for _, opt := range opts {
		opt(&options)
	}

	var (
		wg      sync.WaitGroup
		zero    O
		input   = make(chan I, options.inputBuf)
		results = make(chan Result[I, O])
	)

	// enqueue result asynchronously since results channel is unbuffered/blocking.
	enqueue := func(in I, out O, err error) {
		go func() {
			results <- Result[I, O]{
				Input:  in,
				Output: out,
				Err:    err,
			}
			wg.Done()
		}()
	}

	ctx, cancel := context.WithCancel(ctx)

	for i := 0; i < options.workers; i++ { // Start workers
		go func() {
			for in := range input { // Process all inputs (channel closed on Join)
				if ctx.Err() != nil { // Skip work if failed fast
					enqueue(in, zero, ctx.Err())
					continue
				}

				out, err := work(ctx, in)
				if options.failFast && err != nil { // Maybe fail fast
					cancel()
				}

				enqueue(in, out, err)
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
	join := func() Results[I, O] {
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
