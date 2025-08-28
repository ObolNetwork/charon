// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package lifecycle

import (
	"bytes"
	"context"
	"runtime/pprof"
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

	// SyncBackground defines a start hook that will be called synchronously (blocking)
	// with a fresh background context. Processes that support graceful shutdown can
	// associate this with a call to RegisterStop.
	SyncBackground

	// AsyncBackground defines a start hook that will be called asynchronously (non-blocking)
	// with a fresh background context. Processes that support graceful shutdown can
	// associate this with a call to RegisterStop.
	AsyncBackground
)

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

// runHooks starts and stops all the provided hooks.
func runHooks(appCtx context.Context, startHooks []hook, stopHooks []hook) error {
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

	// backgroundCtx is never closed, it is provided to StartSyncBackground and StartAsyncBackground hooks,
	// they are explicitly stopped.
	backgroundCtx := log.WithTopic(context.Background(), "app-start")

	err := startAllHooks(startAppCtx, backgroundCtx, startHooks, cancel, cacheErr)
	if err != nil {
		return err
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

	stopAllHooks(stopCtx, stopHooks, cancel, cacheErr)

	cacheErr(nil) // Ensure there is something in firstErr.

	return <-firstErr
}

// startHook starts a hook, block until it returns.
func startHook(ctx context.Context, hook hook, cancel context.CancelFunc, cacheErr func(err error)) {
	err := hook.Func.Call(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		cacheErr(errors.Wrap(err, "start hook", z.Str("hook", hook.Label)))
		cancel()
	}
}

// startAllHooks starts all hooks from hook collection.
func startAllHooks(
	startAppCtx context.Context,
	backgroundCtx context.Context,
	startHooks []hook,
	cancel context.CancelFunc,
	cacheErr func(err error),
) error {
	for _, h := range startHooks {
		if startAppCtx.Err() != nil {
			return nil //nolint:nilerr // Just return when ctx closed.
		}

		switch h.StartType {
		case AsyncAppCtx:
			go func(h hook) {
				startHook(startAppCtx, h, cancel, cacheErr)
			}(h)
		case SyncBackground:
			startHook(backgroundCtx, h, cancel, cacheErr)
		case AsyncBackground:
			go func(h hook) {
				startHook(backgroundCtx, h, cancel, cacheErr)
			}(h)
		default:
			return errors.New("unexpected hook type", z.Any("type", h.StartType))
		}
	}

	return nil
}

// stopHook stops a hook, block until it returns.
func stopHook(stopCtx context.Context, hook hook, cancel context.CancelFunc, cacheErr func(err error)) {
	err := hook.Func.Call(stopCtx)
	if errors.Is(stopCtx.Err(), context.DeadlineExceeded) {
		cacheErr(errors.New("shutdown timeout", z.Str("hook", hook.Label), z.Str("stack_dump", getStackDump())))
	} else if err != nil && !errors.Is(err, context.Canceled) {
		cacheErr(errors.Wrap(err, "stop hook", z.Str("hook", hook.Label)))
		cancel() // Cancel the graceful stop context.
	}
}

// stopAllHooks stops all hooks from hooks collection.
func stopAllHooks(stopCtx context.Context, stopHooks []hook, cancel context.CancelFunc, cacheErr func(err error)) {
	for _, hook := range stopHooks {
		if stopCtx.Err() != nil {
			break
		}

		stopHook(stopCtx, hook, cancel, cacheErr)
	}
}

// getStackDump returns a stack dump of all goroutines.
// This is handy to debug shutdown timeout issues.
// See https://stackoverflow.com/questions/19094099/how-to-dump-goroutine-stacktraces.
func getStackDump() string {
	var buf bytes.Buffer

	_ = pprof.Lookup("goroutine").WriteTo(&buf, 2)

	return buf.String()
}
