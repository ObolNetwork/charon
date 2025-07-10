// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package expbackoff implements exponential backoff. It was copied from google.golang.org/grpc.
package expbackoff

import (
	"context"
	"math/rand"
	"testing"
	"time"
)

// Config defines the configuration options for backoff.
type Config struct {
	// BaseDelay is the amount of time to backoff after the first failure.
	BaseDelay time.Duration
	// Multiplier is the factor with which to multiply backoffs after a
	// failed retry. Should ideally be greater than 1.
	Multiplier float64
	// Jitter is the factor with which backoffs are randomized.
	Jitter float64
	// MaxDelay is the upper bound of backoff delay.
	MaxDelay time.Duration
}

// DefaultConfig is a backoff configuration with the default values specified
// at https://github.com/grpc/grpc/blob/master/doc/connection-backoff.md.
//
// This should be useful for callers who want to configure backoff with
// non-default values only for a subset of the options.
//
// Copied from google.golang.org/grpc@v1.48.0/backoff/backoff.go.
var DefaultConfig = Config{
	BaseDelay:  1.0 * time.Second,
	Multiplier: 1.6,
	Jitter:     0.2,
	MaxDelay:   120 * time.Second,
}

// FastConfig is a common configuration for fast backoff.
var FastConfig = Config{
	BaseDelay:  100 * time.Millisecond,
	Multiplier: 1.6,
	Jitter:     0.2,
	MaxDelay:   5 * time.Second,
}

// WithFastConfig configures the backoff with FastConfig.
func WithFastConfig() func(*Config) {
	return func(config *Config) {
		*config = FastConfig
	}
}

// WithConfig configures the backoff with the provided config.
func WithConfig(c Config) func(*Config) {
	return func(config *Config) {
		*config = c
	}
}

// WithMaxDelay configures the backoff with the provided max delay.
func WithMaxDelay(d time.Duration) func(*Config) {
	return func(config *Config) {
		config.MaxDelay = d
	}
}

// WithBaseDelay configures the backoff with the provided max delay.
func WithBaseDelay(d time.Duration) func(*Config) {
	return func(config *Config) {
		config.BaseDelay = d
	}
}

// New returns a backoff function configured via functional options applied to DefaultConfig.
// The backoff function will exponentially sleep longer each time it is called.
// The backoff function returns immediately after the context is cancelled.
//
// Usage:
//
//	backoff := expbackoff.New(ctx)
//	for ctx.Err() == nil {
//	  resp, err := doThing(ctx)
//	  if err != nil {
//	    backoff()
//	    continue
//	  } else {
//	    return resp
//	  }
//	}
func New(ctx context.Context, opts ...func(*Config)) (backoff func()) {
	backoff, _ = NewWithReset(ctx, opts...)
	return backoff
}

// NewWithReset returns a backoff and a reset function configured via functional options applied to DefaultConfig.
// The backoff function will exponentially sleep longer each time it is called.
// Calling the reset function will reset the backoff sleep duration to Config.BaseDelay.
// The backoff function returns immediately after the context is cancelled.
//
// Usage:
//
//	backoff, reset := expbackoff.NewWithReset(ctx)
//	for ctx.Err() == nil {
//	  resp, err := doThing(ctx)
//	  if err != nil {
//	    backoff()
//	    continue
//	  } else {
//	    reset()
//	    // Do something with the response.
//	  }
//	}
func NewWithReset(ctx context.Context, opts ...func(*Config)) (backoff func(), reset func()) {
	conf := DefaultConfig
	for _, opt := range opts {
		opt(&conf)
	}

	var retries int

	backoff = func() {
		if ctx.Err() != nil {
			return
		}

		select {
		case <-ctx.Done():
		case <-after(Backoff(conf, retries)):
		}

		retries++
	}

	reset = func() {
		retries = 0
	}

	return backoff, reset
}

// Backoff returns the amount of time to wait before the next retry given the
// number of retries.
// Copied from google.golang.org/grpc@v1.48.0/internal/backoff/backoff.go.
func Backoff(config Config, retries int) time.Duration {
	if retries == 0 {
		return config.BaseDelay
	}

	backoff := float64(config.BaseDelay)
	maxVal := float64(config.MaxDelay)

	for backoff < maxVal && retries > 0 {
		backoff *= config.Multiplier
		retries--
	}

	if backoff > maxVal {
		backoff = maxVal
	}
	// Randomize backoff delays so that if a cluster of requests start at
	// the same time, they won't operate in lockstep.
	backoff *= 1 + config.Jitter*(randFloat()*2-1)
	if backoff < 0 {
		return 0
	}

	return time.Duration(backoff)
}

// after is aliased for testing.
var after = time.After

// SetAfterForT sets the after internal function for testing.
func SetAfterForT(t *testing.T, fn func(d time.Duration) <-chan time.Time) {
	t.Helper()

	cached := after
	after = fn

	t.Cleanup(func() {
		after = cached
	})
}

// randFloat is aliased for testing.
var randFloat = rand.Float64

// SetRandFloatForT sets the random float internal function for testing.
func SetRandFloatForT(t *testing.T, fn func() float64) {
	t.Helper()

	cached := randFloat
	randFloat = fn

	t.Cleanup(func() {
		randFloat = cached
	})
}
