// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package forkschedule

import (
	"context"
	"math"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/promauto"
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

			schedule, err := fetchFreshest(t.Context(), eth2wrap.NewMultiForT(clients, nil), addrs, log.Filter())
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

	schedule, done, err := start(ctx, eth2Cl, addrs, period, clockwork.NewRealClock())
	require.NoError(t, err)

	t.Cleanup(func() {
		cancel()
		<-done
	})

	return schedule
}

// timingOutNode is an active beacon node timing out on its spec, which makes a scoped client
// fall back to the fallback beacon nodes.
type timingOutNode struct {
	eth2wrap.Client
}

func (timingOutNode) Spec(context.Context, *eth2api.SpecOpts) (*eth2api.Response[map[string]any], error) {
	return nil, errors.New("http request timeout")
}

// TestFetchFreshestIgnoresFallbacks asserts a primary failing to provide its schedule doesn't
// have a fallback's schedule applied in its place.
func TestFetchFreshestIgnoresFallbacks(t *testing.T) {
	behind := newNode(t, unscheduled, true)
	timingOut := timingOutNode{Client: newNode(t, 100, true)}
	fallback := newNode(t, 200, true)

	eth2Cl := eth2wrap.NewMultiForT([]eth2wrap.Client{behind, timingOut}, []eth2wrap.Client{fallback})

	schedule, err := fetchFreshest(t.Context(), eth2Cl, []string{behind.Address(), timingOut.Address()}, log.Filter())
	require.NoError(t, err)
	require.Equal(t, unscheduled, schedule[eth2wrap.Gloas].Epoch)
}

func TestEpochAt(t *testing.T) {
	genesis := time.Unix(1_000_000, 0)

	require.Equal(t, eth2p0.Epoch(0), epochAt(genesis, 12*time.Second, 32, genesis.Add(-time.Hour)), "pre-genesis")
	require.Equal(t, eth2p0.Epoch(0), epochAt(genesis, 12*time.Second, 32, genesis))
	require.Equal(t, eth2p0.Epoch(1), epochAt(genesis, 12*time.Second, 32, genesis.Add(32*12*time.Second)))
	require.Equal(t, eth2p0.Epoch(2), epochAt(genesis, 12*time.Second, 32, genesis.Add(65*12*time.Second)))
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

func TestSetForkMetrics(t *testing.T) {
	schedule := eth2wrap.ForkForkSchedule{
		eth2wrap.Altair:  {Epoch: 0},
		eth2wrap.Electra: {Epoch: 0},
		eth2wrap.Fulu:    {Epoch: 0},
		eth2wrap.Gloas:   {Epoch: 100},
	}

	tests := []struct {
		name     string
		schedule eth2wrap.ForkForkSchedule
		epoch    eth2p0.Epoch
		current  map[string]float64
		next     map[string]float64
	}{
		{
			name:     "next fork scheduled",
			schedule: schedule,
			epoch:    50,
			current:  map[string]float64{"fulu": 0},
			next:     map[string]float64{"gloas": 100},
		},
		{
			name:     "at the fork epoch",
			schedule: schedule,
			epoch:    100,
			current:  map[string]float64{"gloas": 100},
			next:     map[string]float64{},
		},
		{
			name: "next fork unscheduled",
			schedule: eth2wrap.ForkForkSchedule{
				eth2wrap.Fulu:  {Epoch: 10},
				eth2wrap.Gloas: {Epoch: unscheduled},
			},
			epoch:   50,
			current: map[string]float64{"fulu": 10},
			next:    map[string]float64{},
		},
		{
			name:     "no fork active",
			schedule: eth2wrap.ForkForkSchedule{eth2wrap.Altair: {Epoch: 10}},
			epoch:    5,
			current:  map[string]float64{"phase0": 0},
			next:     map[string]float64{"altair": 10},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setForkMetrics(test.schedule, test.epoch)

			require.Equal(t, test.current, gaugeValues(t, "app_fork_current_activation_epoch"))
			require.Equal(t, test.next, gaugeValues(t, "app_fork_next_activation_epoch"))
		})
	}
}

// gaugeValues returns the values of the named gauge by fork label.
func gaugeValues(t *testing.T, name string) map[string]float64 {
	t.Helper()

	registry, err := promauto.NewRegistry(nil)
	require.NoError(t, err)

	families, err := registry.Gather()
	require.NoError(t, err)

	resp := make(map[string]float64)

	for _, family := range families {
		if family.GetName() != name {
			continue
		}

		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "fork" {
					resp[label.GetValue()] = metric.GetGauge().GetValue()
				}
			}
		}
	}

	return resp
}

// restartableNode is a beacon node that can be restarted with a different spec. Its address is
// kept across restarts, like a restarted beacon node behind the same endpoint.
type restartableNode struct {
	eth2wrap.Client

	mu     sync.RWMutex
	spec   eth2wrap.Client
	active bool
}

func newRestartableNode(t *testing.T, gloasEpoch eth2p0.Epoch) *restartableNode {
	t.Helper()

	node := newNode(t, gloasEpoch, true)

	return &restartableNode{Client: node, spec: node, active: true}
}

func (n *restartableNode) Spec(ctx context.Context, opts *eth2api.SpecOpts) (*eth2api.Response[map[string]any], error) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	return n.spec.Spec(ctx, opts)
}

func (n *restartableNode) IsActive() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()

	return n.active
}

// stop makes the node inactive, as when it is shut down.
func (n *restartableNode) stop() {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.active = false
}

// start makes the node active again, scheduling gloas at the epoch.
func (n *restartableNode) start(t *testing.T, gloasEpoch eth2p0.Epoch) {
	t.Helper()

	spec := newNode(t, gloasEpoch, true)

	n.mu.Lock()
	defer n.mu.Unlock()

	n.spec = spec
	n.active = true
}

// TestBeaconNodeRestart asserts that of two beacon nodes, the one restarted with gloas scheduled
// sooner has its schedule applied, while the other keeps running with its previous schedule.
func TestBeaconNodeRestart(t *testing.T) {
	const (
		farEpoch   = eth2p0.Epoch(1_000_000_000)
		soonEpoch  = eth2p0.Epoch(100)
		waitPeriod = 5 * time.Second
		refresh    = 10 * time.Millisecond
	)

	tests := []struct {
		name    string
		initial eth2p0.Epoch // Gloas epoch of both nodes before the restart.
	}{
		{name: "gloas unscheduled", initial: unscheduled},
		{name: "gloas scheduled far away", initial: farEpoch},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nodeA := newRestartableNode(t, test.initial)
			nodeB := newRestartableNode(t, test.initial)

			schedule := startForT(t,
				eth2wrap.NewMultiForT([]eth2wrap.Client{nodeA, nodeB}, nil),
				[]string{nodeA.Address(), nodeB.Address()},
				refresh)
			require.Equal(t, test.initial, schedule()[eth2wrap.Gloas].Epoch)

			// While node B restarts, node A's schedule is applied.
			nodeB.stop()
			time.Sleep(10 * refresh)
			require.Equal(t, test.initial, schedule()[eth2wrap.Gloas].Epoch)

			// Node B is back with gloas scheduled sooner, which is applied.
			nodeB.start(t, soonEpoch)
			require.Eventually(t, func() bool {
				return schedule()[eth2wrap.Gloas].Epoch == soonEpoch
			}, waitPeriod, refresh)

			// Node A still publishes its previous schedule, the sooner epoch stays applied.
			require.Equal(t, test.initial, gloasEpochOf(t, nodeA))

			time.Sleep(10 * refresh)
			require.Equal(t, soonEpoch, schedule()[eth2wrap.Gloas].Epoch)
		})
	}
}

// gloasEpochOf returns the gloas epoch published by the beacon node.
func gloasEpochOf(t *testing.T, node eth2wrap.Client) eth2p0.Epoch {
	t.Helper()

	schedule, err := eth2wrap.FetchForkConfig(t.Context(), node)
	require.NoError(t, err)

	return schedule[eth2wrap.Gloas].Epoch
}

func TestConflicts(t *testing.T) {
	schedule := func(gloas eth2p0.Epoch) eth2wrap.ForkForkSchedule {
		return eth2wrap.ForkForkSchedule{
			eth2wrap.Fulu:  {Epoch: 10},
			eth2wrap.Gloas: {Epoch: gloas},
		}
	}

	tests := []struct {
		name      string
		schedules []eth2wrap.ForkForkSchedule
		want      map[eth2wrap.Fork][]eth2p0.Epoch
	}{
		{
			name:      "agree",
			schedules: []eth2wrap.ForkForkSchedule{schedule(100), schedule(100)},
			want:      map[eth2wrap.Fork][]eth2p0.Epoch{},
		},
		{
			name:      "unscheduled doesn't conflict",
			schedules: []eth2wrap.ForkForkSchedule{schedule(unscheduled), schedule(100)},
			want:      map[eth2wrap.Fork][]eth2p0.Epoch{},
		},
		{
			name:      "postponed fork",
			schedules: []eth2wrap.ForkForkSchedule{schedule(200), schedule(unscheduled), schedule(100)},
			want:      map[eth2wrap.Fork][]eth2p0.Epoch{eth2wrap.Gloas: {100, 200}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, conflicts(test.schedules))
		})
	}
}

func TestFetchFreshestReportsConflicts(t *testing.T) {
	fetch := func(nodes ...beaconmock.Mock) eth2wrap.ForkForkSchedule {
		var (
			clients []eth2wrap.Client
			addrs   []string
		)

		for _, node := range nodes {
			clients = append(clients, node)
			addrs = append(addrs, node.Address())
		}

		schedule, err := fetchFreshest(t.Context(), eth2wrap.NewMultiForT(clients, nil), addrs, log.Filter())
		require.NoError(t, err)

		return schedule
	}

	// The earliest epoch still applies, reporting the conflict.
	schedule := fetch(newNode(t, 200, true), newNode(t, 100, true))
	require.Equal(t, eth2p0.Epoch(100), schedule[eth2wrap.Gloas].Epoch)
	require.Equal(t, map[string]float64{"gloas": 1}, gaugeValues(t, "app_fork_schedule_conflict"))

	// Once the nodes agree, the conflict is cleared.
	fetch(newNode(t, 100, true), newNode(t, 100, true))
	require.Empty(t, gaugeValues(t, "app_fork_schedule_conflict"))
}

// TestStartEpochRollover asserts the fork metrics follow the clock across the fork epoch.
func TestStartEpochRollover(t *testing.T) {
	const gloasEpoch = 100

	genesis := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	node, err := beaconmock.New(t.Context(),
		beaconmock.WithGenesisTime(genesis),
		beaconmock.WithSpecOverride("GLOAS_FORK_VERSION", "0x07000000"),
		beaconmock.WithSpecOverride("GLOAS_FORK_EPOCH", strconv.Itoa(gloasEpoch)),
	)
	require.NoError(t, err)

	node.IsActiveFunc = func() bool { return true }

	slotDuration, slotsPerEpoch, err := eth2wrap.FetchSlotsConfig(t.Context(), node)
	require.NoError(t, err)

	forkStart := genesis.Add(time.Duration(gloasEpoch*slotsPerEpoch) * slotDuration)
	clock := clockwork.NewFakeClockAt(forkStart.Add(-time.Second))

	ctx, cancel := context.WithCancel(t.Context())

	_, done, err := start(ctx, eth2wrap.NewMultiForT([]eth2wrap.Client{node}, nil), []string{node.Address()}, time.Minute, clock)
	require.NoError(t, err)

	t.Cleanup(func() {
		cancel()
		<-done
	})

	require.Equal(t, map[string]float64{"gloas": gloasEpoch}, gaugeValues(t, "app_fork_next_activation_epoch"))

	require.NoError(t, clock.BlockUntilContext(ctx, 1)) // The refresh ticker.
	clock.Advance(time.Minute)

	require.Eventually(t, func() bool {
		return gaugeValues(t, "app_fork_current_activation_epoch")["gloas"] == gloasEpoch
	}, 5*time.Second, 10*time.Millisecond)
	require.NotContains(t, gaugeValues(t, "app_fork_next_activation_epoch"), "gloas")
}
