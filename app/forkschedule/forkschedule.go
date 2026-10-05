// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package forkschedule provides the fork schedule charon applies, refreshed at runtime so that a
// fork scheduled after startup applies without a restart.
package forkschedule

import (
	"context"
	"sync"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// refreshPeriod is the period at which the fork schedule is refreshed. The beacon node clients
// cache the spec, so a refresh rarely leads to a request.
const refreshPeriod = time.Minute

// Start fetches the fork schedule and refreshes it periodically until the context is cancelled,
// returning a function providing the schedule to apply.
//
// The schedule is the freshest of the active primary beacon nodes at the addresses: per fork the
// earliest scheduled epoch, since a beacon node that hasn't scheduled a fork yet publishes it
// with epoch math.MaxUint64. An inactive node is skipped, and read afresh once active again since
// its client drops the cached spec when the node becomes inactive, e.g. while restarting.
//
// TODO(post-gloas): replace with a generic "best" response strategy across beacon nodes.
func Start(ctx context.Context, eth2Cl eth2wrap.Client, addrs []string) (func() eth2wrap.ForkForkSchedule, error) {
	schedule, _, err := start(ctx, eth2Cl, addrs, refreshPeriod)

	return schedule, err
}

// start is Start with the refresh period, also returning a channel closed once refreshing stopped.
func start(ctx context.Context, eth2Cl eth2wrap.Client, addrs []string, period time.Duration,
) (func() eth2wrap.ForkForkSchedule, <-chan struct{}, error) {
	applied, err := fetchFreshest(ctx, eth2Cl, addrs)
	if err != nil {
		// E.g. on startup with only a fallback beacon node up.
		applied, err = eth2wrap.FetchForkConfig(ctx, eth2Cl)
		if err != nil {
			return nil, nil, errors.Wrap(err, "fetch fork schedule")
		}
	}

	var mu sync.RWMutex

	done := make(chan struct{})

	go func() {
		defer close(done)

		ticker := time.NewTicker(period)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			schedule, err := fetchFreshest(ctx, eth2Cl, addrs)
			if err != nil {
				log.Debug(ctx, "Keeping fork schedule", z.Err(err))
				continue
			}

			mu.Lock()
			logChanges(ctx, applied, schedule)
			applied = schedule
			mu.Unlock()
		}
	}()

	return func() eth2wrap.ForkForkSchedule {
		mu.RLock()
		defer mu.RUnlock()

		return applied
	}, done, nil
}

// fetchFreshest returns the freshest fork schedule of the active beacon nodes at the addresses.
func fetchFreshest(ctx context.Context, eth2Cl eth2wrap.Client, addrs []string) (eth2wrap.ForkForkSchedule, error) {
	var schedules []eth2wrap.ForkForkSchedule

	for i, addr := range addrs {
		cl := eth2Cl.ClientForAddress(addr)
		if !cl.IsActive() {
			continue
		}

		schedule, err := eth2wrap.FetchForkConfig(ctx, cl)
		if err != nil {
			// The index identifies the node without logging its address, which may hold credentials.
			log.Warn(ctx, "Failed to fetch beacon node fork schedule", err, z.Int("beacon_node_index", i))
			continue
		}

		schedules = append(schedules, schedule)
	}

	if len(schedules) == 0 {
		return nil, errors.New("no active beacon node")
	}

	return freshest(schedules), nil
}

// freshest returns the freshest of the schedules: per fork the earliest scheduled epoch.
func freshest(schedules []eth2wrap.ForkForkSchedule) eth2wrap.ForkForkSchedule {
	resp := make(eth2wrap.ForkForkSchedule)

	for _, schedule := range schedules {
		for fork, fs := range schedule {
			if current, ok := resp[fork]; !ok || fs.Epoch < current.Epoch {
				resp[fork] = fs
			}
		}
	}

	return resp
}

// logChanges logs the forks whose epoch differs between the schedules.
func logChanges(ctx context.Context, previous, current eth2wrap.ForkForkSchedule) {
	for fork, fs := range current {
		if previous[fork].Epoch != fs.Epoch {
			log.Info(ctx, "Applied updated fork schedule", z.Str("fork", fork.String()),
				z.U64("epoch", uint64(fs.Epoch)), z.U64("previous_epoch", uint64(previous[fork].Epoch)))
		}
	}
}
