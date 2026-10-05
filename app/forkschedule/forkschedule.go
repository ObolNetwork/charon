// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package forkschedule provides the fork schedule charon applies, refreshed at runtime so that a
// fork scheduled after startup applies without a restart.
package forkschedule

import (
	"context"
	"maps"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"
	"golang.org/x/time/rate"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

const (
	// refreshPeriod is the period at which the fork schedule is refreshed. The beacon node clients
	// cache the spec, so a refresh rarely leads to a request.
	refreshPeriod = time.Minute

	// conflictLogPeriod rate limits the warning about beacon nodes scheduling a fork at different epochs.
	conflictLogPeriod = 10 * time.Minute
)

// Start fetches the fork schedule and refreshes it periodically until the context is cancelled,
// returning a function providing the schedule to apply.
//
// The schedule is the freshest of the active primary beacon nodes at the addresses: per fork the
// earliest scheduled epoch, since a beacon node that hasn't scheduled a fork yet publishes it
// with epoch math.MaxUint64. An inactive node is skipped, and read afresh once active again since
// its client drops the cached spec when the node becomes inactive, e.g. while restarting. Nodes
// scheduling a fork at different epochs, e.g. after it was postponed, are reported.
//
// TODO(post-gloas): replace with a generic "best" response strategy across beacon nodes.
func Start(ctx context.Context, eth2Cl eth2wrap.Client, addrs []string) (func() eth2wrap.ForkForkSchedule, error) {
	schedule, _, err := start(ctx, eth2Cl, addrs, refreshPeriod, clockwork.NewRealClock())

	return schedule, err
}

// start is Start with the refresh period and clock, also returning a channel closed once refreshing stopped.
func start(ctx context.Context, eth2Cl eth2wrap.Client, addrs []string, period time.Duration, clock clockwork.Clock,
) (func() eth2wrap.ForkForkSchedule, <-chan struct{}, error) {
	genesisTime, err := eth2wrap.FetchGenesisTime(ctx, eth2Cl)
	if err != nil {
		return nil, nil, err
	}

	slotDuration, slotsPerEpoch, err := eth2wrap.FetchSlotsConfig(ctx, eth2Cl)
	if err != nil {
		return nil, nil, err
	}

	currentEpoch := func() eth2p0.Epoch {
		return epochAt(genesisTime, slotDuration, slotsPerEpoch, clock.Now())
	}

	conflictFilter := log.Filter(log.WithFilterRateLimit(rate.Every(conflictLogPeriod)))

	applied, err := fetchFreshest(ctx, eth2Cl, addrs, conflictFilter)
	if err != nil {
		// E.g. on startup with only a fallback beacon node up.
		applied, err = eth2wrap.FetchForkConfig(ctx, eth2Cl)
		if err != nil {
			return nil, nil, errors.Wrap(err, "fetch fork schedule")
		}
	}

	setForkMetrics(applied, currentEpoch())

	var mu sync.RWMutex

	done := make(chan struct{})

	go func() {
		defer close(done)

		ticker := clock.NewTicker(period)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.Chan():
			}

			schedule, err := fetchFreshest(ctx, eth2Cl, addrs, conflictFilter)
			if err != nil {
				log.Debug(ctx, "Keeping fork schedule", z.Err(err))
			} else {
				mu.Lock()
				logChanges(ctx, applied, schedule)
				applied = schedule
				mu.Unlock()
			}

			// Applied is only written by this goroutine, so it is safe to read without the lock.
			setForkMetrics(applied, currentEpoch())
		}
	}()

	return func() eth2wrap.ForkForkSchedule {
		mu.RLock()
		defer mu.RUnlock()

		return applied
	}, done, nil
}

// fetchFreshest returns the freshest fork schedule of the active beacon nodes at the addresses,
// reporting forks they schedule at different epochs with the conflict log filter.
func fetchFreshest(ctx context.Context, eth2Cl eth2wrap.Client, addrs []string, conflictFilter z.Field) (eth2wrap.ForkForkSchedule, error) {
	var schedules []eth2wrap.ForkForkSchedule

	for i, addr := range addrs {
		// Without fallbacks, which a scoped client otherwise queries when the node fails.
		cl := eth2wrap.PrimaryOnly(eth2Cl.ClientForAddress(addr))
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

	reportConflicts(ctx, conflicts(schedules), conflictFilter)

	return freshest(schedules), nil
}

// conflicts returns the forks the schedules set at different epochs, with the sorted distinct
// epochs. An unscheduled fork doesn't conflict, since a node not yet upgraded publishes it so.
func conflicts(schedules []eth2wrap.ForkForkSchedule) map[eth2wrap.Fork][]eth2p0.Epoch {
	epochs := make(map[eth2wrap.Fork]map[eth2p0.Epoch]bool)

	for _, schedule := range schedules {
		for fork, fs := range schedule {
			if fs.Epoch == math.MaxUint64 {
				continue
			}

			if epochs[fork] == nil {
				epochs[fork] = make(map[eth2p0.Epoch]bool)
			}

			epochs[fork][fs.Epoch] = true
		}
	}

	resp := make(map[eth2wrap.Fork][]eth2p0.Epoch)

	for fork, set := range epochs {
		if len(set) > 1 {
			resp[fork] = slices.Sorted(maps.Keys(set))
		}
	}

	return resp
}

// reportConflicts sets the schedule conflict metric and warns about each conflicting fork. The
// earliest epoch still applies, as with a fork scheduled by only some nodes, which also matches
// a postponed fork's beacon nodes that aren't upgraded yet, so operators must check them.
func reportConflicts(ctx context.Context, conflicts map[eth2wrap.Fork][]eth2p0.Epoch, filter z.Field) {
	scheduleConflictGauge.Reset()

	for fork, epochs := range conflicts {
		label := strings.ToLower(fork.String())

		scheduleConflictGauge.WithLabelValues(label).Set(1)

		log.Warn(ctx, "Beacon nodes schedule a fork at different epochs, applying the earliest. "+
			"Check the beacon nodes run the same network configuration, e.g. after a fork was postponed", nil,
			z.Str("fork", label), z.Any("epochs", epochs), filter)
	}
}

// epochAt returns the epoch at the time, the genesis epoch before genesis.
func epochAt(genesisTime time.Time, slotDuration time.Duration, slotsPerEpoch uint64, now time.Time) eth2p0.Epoch {
	if now.Before(genesisTime) {
		return 0
	}

	return eth2p0.Epoch(uint64(now.Sub(genesisTime)/slotDuration) / slotsPerEpoch)
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

// setForkMetrics sets the current and next fork metrics of the schedule at the epoch. Of forks
// activating at the same epoch, the latest is the current or next one.
func setForkMetrics(schedule eth2wrap.ForkForkSchedule, epoch eth2p0.Epoch) {
	var (
		current, next           = "phase0", ""
		currentEpoch, nextEpoch eth2p0.Epoch
	)

	// In fork order, so that of forks activating at the same epoch the latest one wins.
	for _, fork := range slices.Sorted(maps.Keys(schedule)) {
		fs := schedule[fork]
		if fs.Epoch == math.MaxUint64 {
			continue // Not scheduled.
		}

		label := strings.ToLower(fork.String())

		if fs.Epoch <= epoch && fs.Epoch >= currentEpoch {
			current, currentEpoch = label, fs.Epoch
		} else if fs.Epoch > epoch && (next == "" || fs.Epoch <= nextEpoch) {
			next, nextEpoch = label, fs.Epoch
		}
	}

	currentForkGauge.Reset()
	currentForkGauge.WithLabelValues(current).Set(float64(currentEpoch))

	nextForkGauge.Reset()

	if next != "" {
		nextForkGauge.WithLabelValues(next).Set(float64(nextEpoch))
	}
}
