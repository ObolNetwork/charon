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

// Package lifecycle provides a life cycle manager abstracting the starting and stopping
// of processes by registered start or stop hooks.
//
// The following features as supported:
//  - Start hooks can either be called synchronously or asynchronously.
//  - Start hooks can use the application context (hard shutdown) or background context (graceful shutdown).
//  - Stop hooks are synchronous and use a shutdown context with 10s timeout.
//  - Ordering of start and stop hooks.
//  - Any error from start hooks immediately triggers graceful shutdown.
//  - Closing application context triggers graceful shutdown.
//  - Any error from stop hooks immediately triggers hard shutdown.
package lifecycle

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// IHookFunc is the life cycle hook function interface.
// Users will mostly wrap functions using one of the types below.
type IHookFunc interface {
	Call(context.Context) error
}

// HookFunc wraps a standard hook function (context and error) as a IHookFunc.
type HookFunc func(ctx context.Context) error

func (fn HookFunc) Call(ctx context.Context) error {
	return fn(ctx)
}

// HookFuncMin wraps a minimum (no context, no error) hook function as a IHookFunc.
type HookFuncMin func()

func (fn HookFuncMin) Call(context.Context) error {
	fn()
	return nil
}

// HookFuncErr wraps an error (no context) hook function as a IHookFunc.
type HookFuncErr func() error

func (fn HookFuncErr) Call(context.Context) error {
	return fn()
}

// HookFuncCtx wraps a context (no error) hook function as a IHookFunc.
type HookFuncCtx func(ctx context.Context)

func (fn HookFuncCtx) Call(ctx context.Context) error {
	fn(ctx)
	return nil
}

// HookStartType defines the type of start hook.
type HookStartType int

const (
	// AsyncAppCtx defines a start hook that will be called asynchronously (non-blocking)
	// with the application context. Using the application usually results in hard shutdown.
	AsyncAppCtx HookStartType = iota + 1

	// SyncBackground defines a start hook that wil be called synchronously (blocking)
	// with a fresh background context. Processes that support graceful shutdown can
	// associate this with a call to RegisterStop.
	SyncBackground

	// AsyncBackground defines a start hook that wil be called asynchronously (non-blocking)
	// with a fresh background context. Processes that support graceful shutdown can
	// associate this with a call to RegisterStop.
	AsyncBackground
)

// Manager manages process life cycle by registered start and stop hooks.
type Manager struct {
	mu         sync.Mutex
	started    bool
	startHooks []hook
	stopHooks  []hook
}

// RegisterStart registers a start hook. The type defines whether it is sync or async and which context is used.
// The order defines the order in which hooks are called.
func (m *Manager) RegisterStart(typ HookStartType, order OrderStart, fn IHookFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.started {
		panic("cycle already started")
	}

	m.startHooks = append(m.startHooks, hook{
		Label:     order.String(),
		Order:     int(order),
		StartType: typ,
		Func:      fn,
	})
}

// RegisterStop registers a synchronous stop hook that will be called with the shutdown context that may timeout.
func (m *Manager) RegisterStop(order OrderStop, fn IHookFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.started {
		panic("cycle already started")
	}

	m.stopHooks = append(m.stopHooks, hook{
		Label: order.String(),
		Order: int(order),
		Func:  fn,
	})
}

// Run the lifecycle; start all hooks, waiting for shutdown, stop all hooks.
func (m *Manager) Run(appCtx context.Context) error {
	startHooks := make([]hook, len(m.startHooks))
	stopHooks := make([]hook, len(m.stopHooks))

	m.mu.Lock()

	m.started = true
	copy(startHooks, m.startHooks)
	copy(stopHooks, m.stopHooks)

	m.mu.Unlock()

	sort.Slice(startHooks, func(i, j int) bool {
		return startHooks[i].Order < startHooks[j].Order
	})
	sort.Slice(stopHooks, func(i, j int) bool {
		return stopHooks[i].Order < stopHooks[j].Order
	})

	return run(appCtx, startHooks, stopHooks)
}

// run starts and stops all the provided hooks.
//nolint:contextcheck // Explicit context wrangling.
func run(appCtx context.Context, startHooks, stopHooks []hook) error {
	// Collect any first error, to return at the end.
	firstErr := make(chan error, 1)
	cacheErr := func(err error) {
		select {
		case firstErr <- err:
		default:
			// Some other error already first.
		}
	}

	// startAppCtx is cancelled when app is shutdown or when starting a hook fails.
	startAppCtx, cancel := context.WithCancel(appCtx)
	defer cancel()

	// start a hook, block until it returns.
	start := func(ctx context.Context, hook hook) {
		err := hook.Func.Call(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			cacheErr(errors.Wrap(err, "start hook", z.Str("hook", hook.Label)))
			cancel()
		}
	}

	// backgroundCtx is never closed, it is provided to StartSyncBackground and StartAsyncBackground hooks,
	// they are explicitly stopped.
	backgroundCtx := log.WithTopic(context.Background(), "app-start")

	for _, h := range startHooks {
		if startAppCtx.Err() != nil {
			break
		}

		switch h.StartType {
		case AsyncAppCtx:
			go func(h hook) {
				start(startAppCtx, h)
			}(h)
		case SyncBackground:
			start(backgroundCtx, h)
		case AsyncBackground:
			go func(h hook) {
				start(backgroundCtx, h)
			}(h)
		default:
			return errors.New("unexpected hook type", z.Any("type", h.StartType))
		}
	}

	// Wait for shutdown or hook start failure
	<-startAppCtx.Done()

	if appCtx.Err() != nil {
		log.Info(appCtx, "Shutdown signal detected")
	}

	// stopCtx is a fresh context allowing 10s for shutdown.
	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	stopCtx = log.WithTopic(stopCtx, "app-stop")
	log.Info(stopCtx, "Shutting down gracefully")

	// stop a hook, block until it returns.
	stop := func(hook hook) {
		err := hook.Func.Call(stopCtx)
		if errors.Is(stopCtx.Err(), context.DeadlineExceeded) {
			cacheErr(errors.New("shutdown timeout", z.Str("hook", hook.Label)))
		} else if err != nil && !errors.Is(err, context.Canceled) {
			cacheErr(errors.Wrap(err, "stop hook", z.Str("hook", hook.Label)))
			cancel() // Cancel the graceful stop context.
		}
	}

	for _, hook := range stopHooks {
		if stopCtx.Err() != nil {
			break
		}

		stop(hook)
	}

	cacheErr(nil) // Ensure there is something in firstErr.

	return <-firstErr
}

// hook represents a life cycle hook; either a start or a stop.
type hook struct {
	// Order defines the order in which hooks are called.
	Order int
	// Label is a text label for errors and logging.
	Label string
	// StartType defines whether the start type is (a)synchronous and which context to use.
	StartType HookStartType
	// Func is the hook function.
	Func IHookFunc
}
