// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package shutdowncoord

import (
	"context"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

var sr = registry{
	funcs: map[int][]func() error{},
}

type registry struct {
	funcs map[int][]func() error
	mu    sync.Mutex
}

// RegisterWithUrgency registers f with urgency.
// Higher urgency functions will be executed before lower ones, in a FIFO fashion.
func (sr *registry) registerWithUrgency(f func() error, urgency int) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	urgencySlice, present := sr.funcs[urgency]
	if !present {
		sr.funcs[urgency] = []func() error{f}
		return
	}

	sr.funcs[urgency] = append(urgencySlice, f)
}

func (sr *registry) execute(ctx context.Context) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	type urf struct {
		urgency int
		funcs   []func() error
	}

	var urfs []urf
	for urgency, funcs := range sr.funcs {
		urfs = append(urfs, urf{
			urgency,
			funcs,
		})
	}

	sort.Slice(urfs, func(i, j int) bool {
		return urfs[i].urgency > urfs[j].urgency
	})

	for _, urf := range urfs {
		urctx := log.WithCtx(ctx, z.Int("urgency", urf.urgency))
		log.Debug(urctx, "executing shutdown functions")
		for _, f := range urf.funcs {
			if err := f(); err != nil {
				log.Error(urctx, "error while executing shutdown function", err)
			}
		}
	}
}

// RegisterWithUrgency registers f with urgency.
// Higher urgency functions will be executed before lower ones, in a FIFO fashion.
func RegisterWithUrgency(f func() error, urgency int) {
	sr.registerWithUrgency(f, urgency)
}

// Run listens for SIGINT and calls all the registered shutdown functions in FIFO order, given their urgency.
// Once all the shutdown calls have been executed, the process will exit with error code 1.
func Run() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		sr.execute(context.Background())

		//nolint:revive // needed to kill the entire program, we know this is only done in main.
		os.Exit(1)
	}()
}
