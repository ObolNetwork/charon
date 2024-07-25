// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package lifecycle_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/lifecycle"
)

func TestManager(t *testing.T) {
	const stopHook = lifecycle.HookStartType(-1)

	type hook struct {
		Type  lifecycle.HookStartType
		Order int
	}
	tests := []struct {
		Name         string
		Hooks        []hook
		UnblockStops bool // Set to true of more stop hooks than async start hooks.
		Output       []string
	}{
		{
			Name: "sync stops",
			Hooks: []hook{
				{Type: stopHook, Order: 2},
				{Type: stopHook, Order: 3},
				{Type: stopHook, Order: 1},
			},
			UnblockStops: true,
			Output:       []string{"Stop[1]", "Stop[2]", "Stop[3]"},
		},
		{
			Name: "sync start and stop",
			Hooks: []hook{
				{Type: lifecycle.SyncBackground, Order: 3},
				{Type: lifecycle.SyncBackground, Order: 1},
				{Type: stopHook, Order: 4},
				{Type: stopHook, Order: 2},
			},
			UnblockStops: true,
			Output:       []string{"Start[1,background]", "Start[3,background]", "Stop[2]", "Stop[4]"},
		},
		{
			Name: "async app ctx start",
			// Can't verify orders for async, since not deterministic.
			Hooks: []hook{
				{Type: lifecycle.AsyncBackground},
				{Type: lifecycle.AsyncAppCtx},
				{Type: stopHook},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			proc := &process{
				Calls: make(chan string, len(test.Hooks)*2),
				Stops: make(chan struct{}),
			}

			life := new(lifecycle.Manager)
			starts := 0

			// Register all the hooks
			for _, hook := range test.Hooks {
				if hook.Type == stopHook {
					life.RegisterStop(
						lifecycle.OrderStop(hook.Order),
						proc.Stop(hook.Order),
					)

					continue
				}

				async := hook.Type != lifecycle.SyncBackground
				life.RegisterStart(
					hook.Type,
					lifecycle.OrderStart(hook.Order),
					proc.Start(hook.Order, async),
				)
				starts++
			}

			// If more stop hooks than asynchronous start hooks, manually unblock the stop hooks.
			if test.UnblockStops {
				go func() {
					for {
						<-proc.Stops
					}
				}()
			}

			// Define an identifiable root "app context".
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, struct{}{}))
			defer cancel()

			// Run the lifecycle (async)
			go func() {
				err := life.Run(ctx)
				require.NoError(t, err) //nolint:testifylint // if there is an err it will be caught right away
			}()

			// Wait for the hooks to be called.
			var calls []string
			for i := range len(test.Hooks) {
				if i == starts {
					// Cancel application context after the starts hooks.
					cancel()
				}
				calls = append(calls, <-proc.Calls)
			}

			// Assert all hooks called.
			require.Len(t, calls, len(test.Hooks))

			// Assert output order if specified.
			if len(test.Output) > 0 {
				require.Equal(t, test.Output, calls)
			}
		})
	}
}

// key is a context key to identify root app context.
type key struct{}

// isAppCtx returns true if the context is the tests "app context".
func isAppCtx(ctx context.Context) bool {
	return ctx.Value(key{}) != nil
}

// process is a test process.
type process struct {
	Calls chan string
	Stops chan struct{}
}

// Start returns a hook function with a known order whether it is (a)sync.
func (p *process) Start(order int, async bool) lifecycle.IHookFunc {
	return lifecycle.HookFunc(func(ctx context.Context) error {
		typ := "background"
		if isAppCtx(ctx) {
			typ = "app"
		}

		p.Calls <- fmt.Sprintf("Start[%d,%s]", order, typ)

		// If async, wait for call to stop or ctx cancel.
		if async && isAppCtx(ctx) {
			<-ctx.Done()
		} else if async {
			<-p.Stops
		}

		return nil
	})
}

// Stop returns a hook function with a known order.
func (p *process) Stop(order int) lifecycle.IHookFunc {
	return lifecycle.HookFunc(func(context.Context) error {
		p.Calls <- fmt.Sprintf("Stop[%d]", order)
		p.Stops <- struct{}{}

		return nil
	})
}
