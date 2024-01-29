// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package lifecycle provides a life cycle manager abstracting the starting and stopping
// of processes by registered start or stop hooks.
//
// The following features as supported:
//   - Start hooks can either be called synchronously or asynchronously.
//   - Start hooks can use the application context (hard shutdown) or background context (graceful shutdown).
//   - Stop hooks are synchronous and use a shutdown context with 10s timeout.
//   - Ordering of start and stop hooks.
//   - Any error from start hooks immediately triggers graceful shutdown.
//   - Closing application context triggers graceful shutdown.
//   - Any error from stop hooks immediately triggers hard shutdown.
package lifecycle

import (
	"context"
	"sort"
	"sync"
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

	return runHooks(appCtx, startHooks, stopHooks)
}
