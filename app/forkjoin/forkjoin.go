// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package forkjoin provides an API for "doing work
// concurrently (fork) and then waiting for the results (join)".
package forkjoin

import (
	"context"
	"sync"

	"github.com/obolnetwork/charon/app/errors"
)

const (
	defaultWorkers      = 8
	defaultInputBuf     = 100
	defaultFailFast     = true
	defaultWaitOnCancel = false
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
	inputBuf     int
	workers      int
	failFast     bool
	waitOnCancel bool
}

type Option func(*options)

// WithWaitOnCancel returns an option configuring a forkjoin to wait for all workers to return when canceling.
// The default behaviour just cancels the worker context and closes the output channel without waiting
// for the workers to return.
func WithWaitOnCancel() Option {
	return func(o *options) {
		o.waitOnCancel = true
	}
}

// WithWorkers returns an option configuring a forkjoin with w number of workers.
func WithWorkers(w int) Option {
	return func(o *options) {
		o.workers = w
	}
}

// WithInputBuffer returns an option configuring a forkjoin with an input buffer
// of length i overriding the default of 100.
// Useful to prevent temporary blocking during calls to Fork if enqueuing more than 100 inputs.
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

// New returns fork, join, and cancel functions with generic input type I and output type O.
// It provides an API for "doing work concurrently (fork) and then waiting for the results (join)".
//
// It fails fast by default, stopping execution on any error. All active work function contexts
// are cancelled and no further inputs are executed with remaining result errors being set
// to context cancelled. See WithoutFailFast.
//
// Usage:
//
//	var workFunc := func(ctx context.Context, input MyInput) (MyResult, error) {
//	  ... do work
//	  return result, nil
//	}
//
//	fork, join, cancel := forkjoin.New[MyInput,MyResult](ctx, workFunc)
//	defer cancel() // Release any remaining resources.
//
//	for _, in := range inputs {
//	  fork(in) // Note that calling fork AFTER join panics!
//	}
//
//	resultChan := join()
//
//	// Either read results from the channel as they appear
//	for result := range resultChan { ... }
//
//	// Or block until all results are complete and flatten
//	results, firstErr := resultChan.Flatten()
func New[I, O any](rootCtx context.Context, work Work[I, O], opts ...Option) (Fork[I], Join[I, O], context.CancelFunc) {
	options := options{
		workers:      defaultWorkers,
		inputBuf:     defaultInputBuf,
		failFast:     defaultFailFast,
		waitOnCancel: defaultWaitOnCancel,
	}

	for _, opt := range opts {
		opt(&options)
	}

	var (
		wg         sync.WaitGroup
		zero       O
		input      = make(chan I, options.inputBuf)
		results    = make(chan Result[I, O])
		dropOutput = make(chan struct{})
		done       = make(chan struct{})
	)

	workCtx, cancelWorkers := context.WithCancel(rootCtx)

	// enqueue result asynchronously since results channel is unbuffered/blocking.
	enqueue := func(in I, out O, err error) {
		go func() {
			select {
			case results <- Result[I, O]{
				Input:  in,
				Output: out,
				Err:    err,
			}:
			case <-dropOutput:
				// Dropping output.
			}
			wg.Done()
		}()
	}

	for i := 0; i < options.workers; i++ { // Start workers
		go func() {
			for in := range input { // Process all inputs (channel closed on Join)
				if workCtx.Err() != nil { // Skip work if failed fast
					enqueue(in, zero, workCtx.Err())
					continue
				}

				out, err := work(workCtx, in)
				if options.failFast && err != nil { // Maybe fail fast
					cancelWorkers()
				}

				enqueue(in, out, err)
			}
		}()
	}

	// Fork enqueues inputs, keeping track of how many was enqueued.
	fork := func(i I) {
		var added bool
		defer func() {
			// Handle panic use-case as well as rootCtx done.
			if !added {
				wg.Done()
			}
		}()

		wg.Add(1)
		select {
		case input <- i:
			added = true
		case <-rootCtx.Done():
		}
	}

	// Join returns the results channel that will contain all the results in the future.
	// It also closes the input queue (causing subsequent calls Fork to panic)
	// It also starts a shutdown goroutine that closes the results channel when processing completed
	join := func() Results[I, O] {
		close(input)

		go func() {
			// Auto close result channel when done
			wg.Wait()
			close(results)
			close(done)
		}()

		return results
	}

	// cancel, drop remaining results and cancel workers if not done already.
	cancel := func() {
		close(dropOutput)
		cancelWorkers()
		if options.waitOnCancel {
			<-done
		}
	}

	return fork, join, cancel
}

// NewWithInputs is a convenience function that calls New and then forks all the inputs
// returning the join result and a cancel function.
func NewWithInputs[I, O any](ctx context.Context, work Work[I, O], inputs []I, opts ...Option,
) (Results[I, O], context.CancelFunc) {
	fork, join, cancel := New[I, O](ctx, work, opts...)
	for _, input := range inputs {
		fork(input)
	}

	return join(), cancel
}
