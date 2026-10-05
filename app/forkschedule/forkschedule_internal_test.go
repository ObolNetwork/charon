// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package forkschedule

import (
	"context"
	"math"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

const unscheduled = eth2p0.Epoch(math.MaxUint64)

// newNode returns a beacon mock scheduling gloas at the epoch.
func newNode(t *testing.T, gloasEpoch eth2p0.Epoch, active bool) beaconmock.Mock {
	t.Helper()

	var opts []beaconmock.Option
	if gloasEpoch != unscheduled {
		opts = append(opts,
			beaconmock.WithSpecOverride("GLOAS_FORK_VERSION", "0x07000000"),
			beaconmock.WithSpecOverride("GLOAS_FORK_EPOCH", strconv.FormatUint(uint64(gloasEpoch), 10)),
		)
	}

	bmock, err := beaconmock.New(t.Context(), opts...)
	require.NoError(t, err)

	bmock.IsActiveFunc = func() bool { return active }

	return bmock
}

func TestFreshest(t *testing.T) {
	v1, v2 := eth2p0.Version{1}, eth2p0.Version{2}

	schedule := func(epoch eth2p0.Epoch, version eth2p0.Version) eth2wrap.ForkForkSchedule {
		return eth2wrap.ForkForkSchedule{
			eth2wrap.Fulu:  {Version: eth2p0.Version{6}, Epoch: 10},
			eth2wrap.Gloas: {Version: version, Epoch: epoch},
		}
	}

	tests := []struct {
		name      string
		schedules []eth2wrap.ForkForkSchedule
		want      eth2wrap.ForkSchedule
	}{
		{
			name:      "scheduled beats unscheduled",
			schedules: []eth2wrap.ForkForkSchedule{schedule(unscheduled, v1), schedule(100, v2)},
			want:      eth2wrap.ForkSchedule{Version: v2, Epoch: 100},
		},
		{
			name:      "earliest epoch wins",
			schedules: []eth2wrap.ForkForkSchedule{schedule(100, v1), schedule(50, v2)},
			want:      eth2wrap.ForkSchedule{Version: v2, Epoch: 50},
		},
		{
			name:      "single schedule",
			schedules: []eth2wrap.ForkForkSchedule{schedule(unscheduled, v1)},
			want:      eth2wrap.ForkSchedule{Version: v1, Epoch: unscheduled},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := freshest(test.schedules)
			require.Equal(t, test.want, got[eth2wrap.Gloas])
			require.Equal(t, eth2p0.Epoch(10), got[eth2wrap.Fulu].Epoch)
		})
	}
}

func TestFetchFreshest(t *testing.T) {
	tests := []struct {
		name  string
		nodes []beaconmock.Mock
		want  eth2p0.Epoch
		err   bool
	}{
		{
			name:  "freshest node wins",
			nodes: []beaconmock.Mock{newNode(t, unscheduled, true), newNode(t, 100, true)},
			want:  100,
		},
		{
			name:  "inactive node is skipped",
			nodes: []beaconmock.Mock{newNode(t, unscheduled, true), newNode(t, 100, false)},
			want:  unscheduled,
		},
		{
			name:  "no active node",
			nodes: []beaconmock.Mock{newNode(t, 100, false)},
			err:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var (
				clients []eth2wrap.Client
				addrs   []string
			)

			for _, node := range test.nodes {
				clients = append(clients, node)
				addrs = append(addrs, node.Address())
			}

			schedule, err := fetchFreshest(t.Context(), eth2wrap.NewMultiForT(clients, nil), addrs)
			if test.err {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.want, schedule[eth2wrap.Gloas].Epoch)
		})
	}
}

// startForT starts refreshing with the period, stopping and waiting for it to stop on cleanup,
// since refreshing sets the global fork metrics.
func startForT(t *testing.T, eth2Cl eth2wrap.Client, addrs []string, period time.Duration) func() eth2wrap.ForkForkSchedule {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())

	schedule, done, err := start(ctx, eth2Cl, addrs, period)
	require.NoError(t, err)

	t.Cleanup(func() {
		cancel()
		<-done
	})

	return schedule
}

func TestStart(t *testing.T) {
	active := newNode(t, 100, true)

	schedule := startForT(t, eth2wrap.NewMultiForT([]eth2wrap.Client{active}, nil), []string{active.Address()}, time.Hour)
	require.Equal(t, eth2p0.Epoch(100), schedule()[eth2wrap.Gloas].Epoch)

	// Without an active node, e.g. only a fallback up, the schedule is read through the client.
	fallback := newNode(t, 200, true)
	inactive := newNode(t, 100, false)

	schedule = startForT(t,
		eth2wrap.NewMultiForT([]eth2wrap.Client{inactive}, []eth2wrap.Client{fallback}),
		[]string{inactive.Address()}, time.Hour)
	require.Equal(t, eth2p0.Epoch(100), schedule()[eth2wrap.Gloas].Epoch, "the inactive primary still answers through the client")
}

// TestStartRefresh asserts a beacon node becoming active again, e.g. after a restart, has its
// schedule applied on the next refresh.
func TestStartRefresh(t *testing.T) {
	behind := newNode(t, unscheduled, true)
	fresh := newNode(t, 100, true)

	var freshActive atomic.Bool

	fresh.IsActiveFunc = freshActive.Load

	schedule := startForT(t,
		eth2wrap.NewMultiForT([]eth2wrap.Client{behind, fresh}, nil),
		[]string{behind.Address(), fresh.Address()},
		10*time.Millisecond)
	require.Equal(t, unscheduled, schedule()[eth2wrap.Gloas].Epoch)

	freshActive.Store(true)

	require.Eventually(t, func() bool {
		return schedule()[eth2wrap.Gloas].Epoch == 100
	}, 5*time.Second, 10*time.Millisecond)
}
