// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package scheduler_test

import (
	"context"
	"flag"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/expbackoff"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/scheduler"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

var integration = flag.Bool("integration", false, "enable integration test, requires BEACON_URL vars.")

// TestIntegration runs an integration test for the Scheduler.
// It expects the above flag to enabled and a BEACON_URL env var.
// It then generates a fake manifest with actual mainnet validators
// and logs 10 duties triggered from them.
func TestIntegration(t *testing.T) {
	if !*integration {
		return
	}

	beaconURL, ok := os.LookupEnv("BEACON_URL")
	if !ok {
		t.Fatal("BEACON_URL env var not set")
	}

	eth2Cl, err := eth2wrap.NewMultiHTTP(time.Second*2, [4]byte{}, map[string]string{}, []string{beaconURL}, []string{})
	require.NoError(t, err)

	// Builder registrations for mainnet validators
	valRegs := []*eth2api.VersionedSignedValidatorRegistration{
		{
			Version: eth2spec.BuilderVersionV1,
			V1: &eth2v1.SignedValidatorRegistration{
				Message: &eth2v1.ValidatorRegistration{
					FeeRecipient: beaconmock.MustExecutionAddress("0x388c818ca8b9251b393131c08a736a67ccb19297"),
					GasLimit:     36000000,
					Timestamp:    time.Unix(1606824023, 0),
					Pubkey:       beaconmock.MustBLSPubKey("0x8f4ef114368b24863b369bbf597ace2eab5f77e4726f7931f988ba757fbd1dffd2f44270bbed42d5dfa72e10c79dcb6d"),
				},
				Signature: beaconmock.MustBLSSignature("0xacc05896c51c57177306d3f1eb9de64a6a1fb50b88cf4afe276a3c53673ce1227af2337ef607c769624f45472968cbde15f87c355dfa43bca81c882ea2d89ad301a4ce1c4169874bf9f9b1bafe70838519af34741d774930edbad40a7fefc7e6"),
			},
		},
		{
			Version: eth2spec.BuilderVersionV1,
			V1: &eth2v1.SignedValidatorRegistration{
				Message: &eth2v1.ValidatorRegistration{
					FeeRecipient: beaconmock.MustExecutionAddress("0x388c818ca8b9251b393131c08a736a67ccb19297"),
					GasLimit:     36000000,
					Timestamp:    time.Unix(1606824023, 0),
					Pubkey:       beaconmock.MustBLSPubKey("0xa0753f1bdb24b39441aee027a44af9ec5117a572678aa987944d26d92d332789208cf0733ca99f1d96fae50f7e889c22"),
				},
				Signature: beaconmock.MustBLSSignature("0x8de77931277c745c05879db7e57853a07c5d3bd45d4d5757f55bdf05de3266c6ddac81b3b0316552b2ceb77405aa5c701311db3cd6a6ca176c792a9f1814ede89907b8cd05061a15bfb6618c8390577b349b3b4a75693311f1c638f53c186c58"),
			},
		},
	}

	s, err := scheduler.New(valRegs, eth2Cl, false)
	require.NoError(t, err)

	count := 10

	s.SubscribeDuties(func(ctx context.Context, duty core.Duty, set core.DutyDefinitionSet) error {
		for idx, data := range set {
			t.Logf("Duty triggered: vidx=%v slot=%v committee=%v\n", idx, duty.Slot, data.(core.AttesterDefinition).CommitteeIndex)
		}

		count--
		if count == 0 {
			s.Stop()
		}

		return nil
	})

	require.NoError(t, s.Run())
}

//go:generate go test . -run=TestSchedulerWait -count=20

// TestSchedulerWait tests the waitChainStart and waitBeaconSync functions.
func TestSchedulerWait(t *testing.T) {
	// Eliminate jitter from exponential backoff for deterministic test timing
	expbackoff.SetRandFloatForT(t, func() float64 {
		return 0.5 // Returns middle value, making jitter factor = 0
	})

	tests := []struct {
		Name         string
		GenesisAfter time.Duration
		GenesisErrs  int
		SyncedAfter  time.Duration
		SyncedErrs   int
		WaitSecs     int // Expected wait time in seconds (deterministic with no jitter)
	}{
		{
			Name:     "wait for nothing",
			WaitSecs: 0,
		},
		{
			Name:         "wait for genesis",
			GenesisAfter: time.Second * 5,
			WaitSecs:     5,
		},
		{
			Name:        "wait for sync",
			SyncedAfter: time.Second,
			WaitSecs:    1, // We use expbackoff.DefaultConfig
		},
		{
			Name:        "genesis errors",
			GenesisErrs: 5,
			WaitSecs:    1, // We use expbackoff.FastConfig: 100ms + 160ms + 256ms + 410ms + 656ms ≈ 1582ms
		},
		{
			Name:       "synced errors",
			SyncedErrs: 10,
			WaitSecs:   16, // We use expbackoff.FastConfig with MaxDelay=5s cap (deterministic without jitter)
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			var t0 time.Time

			clock := newTestClock(t0)

			// Set a deadline to prevent the slot ticker goroutine from advancing
			// the clock past the expected wait time. This avoids race conditions
			// where the goroutine advances time before we can measure it.
			expectedEndTime := t0.Add(time.Duration(test.WaitSecs) * time.Second)
			clock.SetDeadline(expectedEndTime)

			eth2Cl, err := beaconmock.New(t.Context())
			require.NoError(t, err)

			eth2Cl.GenesisFunc = func(context.Context, *eth2api.GenesisOpts) (*eth2v1.Genesis, error) {
				var err error
				if test.GenesisErrs > 0 {
					err = errors.New("mock error")
					test.GenesisErrs--
				}

				time := t0.Add(test.GenesisAfter)

				return &eth2v1.Genesis{
					GenesisTime: time,
				}, err
			}

			eth2Cl.NodeSyncingFunc = func(context.Context, *eth2api.NodeSyncingOpts) (*eth2v1.SyncState, error) {
				var err error
				if test.SyncedErrs > 0 {
					err = errors.New("mock error")
					test.SyncedErrs--
				}

				return &eth2v1.SyncState{
					IsSyncing: clock.Now().Before(t0.Add(test.SyncedAfter)),
				}, err
			}

			dd := new(delayer)
			sched := scheduler.NewForT(t, clock, dd.delay, nil, eth2Cl, nil, false)
			sched.Stop() // Just run wait functions, then quit.
			require.NoError(t, sched.Run())

			elapsedSecs := int(clock.Since(t0).Seconds())
			require.Equal(t, test.WaitSecs, elapsedSecs, "Expected %d seconds, got %d", test.WaitSecs, elapsedSecs)
		})
	}
}

//go:generate go test . -run=TestSchedulerDuties -update -clean

// TestSchedulerDuties tests the scheduled duties given a deterministic mock beacon node.
func TestSchedulerDuties(t *testing.T) {
	tests := []struct {
		Name     string
		Factor   int // Determines how duties are spread per epoch
		PropErrs int
		Results  int
	}{
		{
			// All duties grouped in first slot of epoch
			Name:    "grouped",
			Factor:  0,
			Results: 3,
		},
		{
			// All duties spread in first N slots of epoch (N is number of validators)
			Name:    "spread",
			Factor:  1,
			Results: 9,
		},
		{
			// All duties spread in first N slots of epoch (except first proposer errors)
			Name:     "spread_errors",
			Factor:   1,
			PropErrs: 1,
			Results:  8,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			// Configure beacon mock
			var t0 time.Time

			valSet := beaconmock.ValidatorSetA
			eth2Cl, err := beaconmock.New(
				t.Context(),
				beaconmock.WithValidatorSet(valSet),
				beaconmock.WithGenesisTime(t0),
				beaconmock.WithDeterministicAttesterDuties(test.Factor),
				beaconmock.WithDeterministicProposerDuties(test.Factor),
			)
			require.NoError(t, err)

			// Instrument ProposerDuties to returns some errors
			origFunc := eth2Cl.ProposerDutiesFunc
			eth2Cl.ProposerDutiesFunc = func(ctx context.Context, epoch eth2p0.Epoch, indices []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
				if test.PropErrs > 0 {
					test.PropErrs--
					return nil, errors.New("test error")
				}

				return origFunc(ctx, epoch, indices)
			}

			eth2Cl.CachedProposerDutiesFunc = func(ctx context.Context, epoch eth2p0.Epoch, indices []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
				if test.PropErrs > 0 {
					test.PropErrs--
					return nil, errors.New("test error")
				}

				return origFunc(ctx, epoch, indices)
			}

			// Construct scheduler
			clock := newTestClock(t0)
			delayer := new(delayer)
			valRegs := beaconmock.BuilderRegistrationSetA
			sched := scheduler.NewForT(t, clock, delayer.delay, valRegs, eth2Cl, nil, false)

			// Only test scheduler output for first N slots, so Stop scheduler (and slotTicker) after that.
			const stopAfter = 3

			eth2Resp, err := eth2Cl.Spec(t.Context(), &eth2api.SpecOpts{})
			require.NoError(t, err)

			slotDuration, ok := eth2Resp.Data["SECONDS_PER_SLOT"].(time.Duration)
			require.True(t, ok)
			clock.CallbackAfter(t0.Add(time.Duration(stopAfter)*slotDuration), func() {
				time.Sleep(time.Hour) // Do not let the slot ticker tick anymore.
			})

			// Collect results
			type result struct {
				Time       string
				DutyStr    string    `json:"duty"`
				Duty       core.Duty `json:"-"`
				DutyDefSet map[core.PubKey]string
			}

			var (
				results []result
				mu      sync.Mutex
			)

			sched.SubscribeDuties(func(ctx context.Context, duty core.Duty, set core.DutyDefinitionSet) error {
				// Make result human-readable
				resultSet := make(map[core.PubKey]string)

				for pubkey, def := range set {
					b, err := def.MarshalJSON()
					require.NoError(t, err)

					resultSet[pubkey] = string(b)
				}

				// Add result
				mu.Lock()
				defer mu.Unlock()

				results = append(results, result{
					Duty:       duty,
					DutyStr:    duty.String(),
					DutyDefSet: resultSet,
				})

				if len(results) == test.Results {
					sched.Stop()
				}

				return nil
			})

			// Run scheduler
			require.NoError(t, sched.Run())

			// Add deadlines to results
			deadlines := delayer.get()
			for i := range len(results) {
				results[i].Time = deadlines[results[i].Duty].UTC().Format("04:05.000")
			}
			// Make result order deterministic
			sort.Slice(results, func(i, j int) bool {
				if results[i].Duty.Slot == results[j].Duty.Slot {
					return results[i].Duty.Type < results[j].Duty.Type
				}

				return results[i].Duty.Slot < results[j].Duty.Slot
			})

			// Assert results
			testutil.RequireGoldenJSON(t, results)
		})
	}
}

func TestScheduler_GetDuty(t *testing.T) {
	var (
		ctx    = t.Context()
		t0     time.Time
		slot   = uint64(1)
		valSet = beaconmock.ValidatorSetA
	)

	// Configure beacon mock.
	eth2Cl, err := beaconmock.New(
		t.Context(),
		beaconmock.WithValidatorSet(valSet),
		beaconmock.WithGenesisTime(t0),
		beaconmock.WithDeterministicAttesterDuties(0),
		beaconmock.WithDeterministicSyncCommDuties(2, 2),
		beaconmock.WithSlotsPerEpoch(1),
	)
	require.NoError(t, err)

	// Construct scheduler.
	clock := newTestClock(t0)
	dd := new(delayer)
	valRegs := beaconmock.BuilderRegistrationSetA
	sched := scheduler.NewForT(t, clock, dd.delay, valRegs, eth2Cl, nil, false)

	_, err = sched.GetDutyDefinition(ctx, core.NewAttesterDuty(slot))
	require.ErrorContains(t, err, "epoch not resolved yet")

	_, err = sched.GetDutyDefinition(ctx, core.NewAggregatorDuty(slot))
	require.ErrorContains(t, err, "epoch not resolved yet")

	_, err = sched.GetDutyDefinition(ctx, core.NewSyncContributionDuty(slot))
	require.ErrorContains(t, err, "epoch not resolved yet")

	_, err = sched.GetDutyDefinition(ctx, core.Duty{
		Slot: slot,
		Type: core.DutyBuilderProposer,
	})
	require.ErrorIs(t, err, core.ErrDeprecatedDutyBuilderProposer)

	slotDuration, slotsPerEpoch, err := eth2wrap.FetchSlotsConfig(ctx, eth2Cl)
	require.NoError(t, err)

	clock.CallbackAfter(t0.Add(slotDuration).Add(time.Second), func() {
		res, err := sched.GetDutyDefinition(ctx, core.NewAttesterDuty(slot))
		require.NoError(t, err)

		pubKeys, err := valSet.CorePubKeys()
		require.NoError(t, err)

		for _, pubKey := range pubKeys {
			require.NotNil(t, res[pubKey])
		}

		res, err = sched.GetDutyDefinition(ctx, core.NewAggregatorDuty(slot))
		require.NoError(t, err)

		for _, pubKey := range pubKeys {
			require.NotNil(t, res[pubKey])
		}

		res, err = sched.GetDutyDefinition(ctx, core.NewSyncContributionDuty(slot))
		require.NoError(t, err)

		for _, pubKey := range pubKeys {
			require.NotNil(t, res[pubKey])
		}
	})

	// Expire all duties
	const trimEpochOffset = 3

	expiry := time.Duration(trimEpochOffset*slotsPerEpoch) * slotDuration
	clock.CallbackAfter(t0.Add(expiry).Add(time.Minute), func() {
		_, err = sched.GetDutyDefinition(ctx, core.NewAttesterDuty(slot))
		require.ErrorContains(t, err, "epoch already trimmed")

		_, err = sched.GetDutyDefinition(ctx, core.NewAggregatorDuty(slot))
		require.ErrorContains(t, err, "epoch already trimmed")

		_, err = sched.GetDutyDefinition(ctx, core.NewSyncContributionDuty(slot))
		require.ErrorContains(t, err, "epoch already trimmed")

		sched.Stop()
	})

	// Run scheduler
	require.NoError(t, sched.Run())
}

//go:generate go test . -run=TestNoActive -count=100

func TestNoActive(t *testing.T) {
	var (
		ctx          = t.Context()
		t0           = time.Now()
		slotDuration = time.Second
	)

	// Configure beacon mock.
	eth2Cl, err := beaconmock.New(
		t.Context(),
		beaconmock.WithGenesisTime(t0),
		beaconmock.WithSlotDuration(slotDuration),
		beaconmock.WithSlotsPerEpoch(1),
	)
	require.NoError(t, err)

	// Construct scheduler.
	clock := newTestClock(t0)
	dd := new(delayer)
	sched := scheduler.NewForT(t, clock, dd.delay, nil, eth2Cl, nil, false)

	clock.CallbackAfter(t0.Add(slotDuration*2), func() {
		_, err := sched.GetDutyDefinition(ctx, core.NewAttesterDuty(1))
		require.ErrorContains(t, err, "duty not present for resolved epoch")
		sched.Stop()
	})

	require.NoError(t, sched.Run())
}

func TestHandleChainReorgEvent(t *testing.T) {
	var (
		t0     time.Time
		valSet = beaconmock.ValidatorSetA
	)

	featureset.EnableForT(t, featureset.SSEReorgDuties)

	// Configure beacon mock.
	eth2Cl, err := beaconmock.New(
		t.Context(),
		beaconmock.WithValidatorSet(valSet),
		beaconmock.WithGenesisTime(t0),
		beaconmock.WithDeterministicAttesterDuties(1),
		beaconmock.WithSlotsPerEpoch(4),
	)
	require.NoError(t, err)

	// Construct scheduler.
	schedSlotCh := make(chan core.Slot)
	schedSlotFunc := func(ctx context.Context, slot core.Slot) {
		select {
		case <-ctx.Done():
			return
		case schedSlotCh <- slot:
		}
	}
	clock := newTestClock(t0)
	dd := new(delayer)
	valRegs := beaconmock.BuilderRegistrationSetA
	sched := scheduler.NewForT(t, clock, dd.delay, valRegs, eth2Cl, schedSlotFunc, false)

	doneCh := make(chan error, 1)

	go func() {
		doneCh <- sched.Run()

		close(schedSlotCh)
	}()

	for slot := range schedSlotCh {
		clock.Pause()

		switch slot.Slot {
		case 1: // epoch 0
			_, err := sched.GetDutyDefinition(t.Context(), core.NewAttesterDuty(1))
			require.NoError(t, err)
		case 5: // epoch 1
			_, err := sched.GetDutyDefinition(t.Context(), core.NewAttesterDuty(5))
			require.NoError(t, err)
			sched.HandleChainReorgEvent(t.Context(), 0)
			_, err = sched.GetDutyDefinition(t.Context(), core.NewAttesterDuty(5))
			require.ErrorContains(t, err, "epoch not resolved yet")
		case 7: // epoch 1 after reorg
			_, err := sched.GetDutyDefinition(t.Context(), core.NewAttesterDuty(6))
			require.NoError(t, err)
			sched.Stop()
		}

		clock.Resume()
	}

	require.NoError(t, <-doneCh)
}

func TestSubmitValidatorRegistrations(t *testing.T) {
	// The test uses hard-coded validator registrations from beaconmock.BuilderRegistrationSetA.
	// The scheduler advances through 3 epochs to ensure it triggers the registration submission.
	var (
		t0     time.Time
		valSet = beaconmock.ValidatorSetA
	)

	eth2Cl, err := beaconmock.New(
		t.Context(),
		beaconmock.WithValidatorSet(valSet),
		beaconmock.WithGenesisTime(t0),
		beaconmock.WithDeterministicAttesterDuties(1),
		beaconmock.WithSlotsPerEpoch(4),
	)
	require.NoError(t, err)

	// Track calls to SubmitValidatorRegistrations
	var (
		callCount     atomic.Int64
		callMutex     sync.Mutex
		registrations []*eth2api.VersionedSignedValidatorRegistration
		callDone      = make(chan struct{}, 1)
	)

	origFunc := eth2Cl.SubmitValidatorRegistrationsFunc
	eth2Cl.SubmitValidatorRegistrationsFunc = func(ctx context.Context, regs []*eth2api.VersionedSignedValidatorRegistration) error {
		callCount.Add(1)

		if registrations == nil {
			callMutex.Lock()
			registrations = regs
			callMutex.Unlock()

			select {
			case callDone <- struct{}{}:
			default:
			}
		}

		return origFunc(ctx, regs)
	}

	schedSlotCh := make(chan core.Slot)
	schedSlotFunc := func(ctx context.Context, slot core.Slot) {
		select {
		case <-ctx.Done():
			return
		case schedSlotCh <- slot:
		}
	}
	clock := newTestClock(t0)
	dd := new(delayer)
	valRegs := beaconmock.BuilderRegistrationSetA
	sched := scheduler.NewForT(t, clock, dd.delay, valRegs, eth2Cl, schedSlotFunc, true)

	doneCh := make(chan error, 1)

	go func() {
		doneCh <- sched.Run()

		close(schedSlotCh)
	}()

	epochsSeen := make(map[uint64]bool)
	slotCount := 0
	stopped := false

	for slot := range schedSlotCh {
		clock.Pause()

		slotCount++

		if !epochsSeen[slot.Epoch()] {
			epochsSeen[slot.Epoch()] = true
		}

		// Stop after processing enough slots to see 3 epochs and after registration completes
		// With 4 slots per epoch, we need at least 9 slots (slots 0-8 cover epochs 0, 1, 2)
		if slotCount >= 9 && !stopped {
			<-callDone
			stopped = true
			sched.Stop()
		}

		clock.Resume()
	}

	require.NoError(t, <-doneCh)

	count := callCount.Load()
	require.GreaterOrEqual(t, count, int64(1), "Expected at least 1 call to SubmitValidatorRegistrations, got %d", count)
	require.NotNil(t, registrations, "No registrations were captured")
	require.Len(t, registrations, len(valRegs), "Expected %d registrations, got %d", len(valRegs), len(registrations))

	// Verify registration data matches BuilderRegistrationSetA
	for i, reg := range registrations {
		require.Equal(t, valRegs[i].V1.Message.GasLimit, reg.V1.Message.GasLimit)
		require.Equal(t, valRegs[i].V1.Message.Timestamp.Unix(), reg.V1.Message.Timestamp.Unix())
		require.Equal(t, valRegs[i].V1.Message.FeeRecipient, reg.V1.Message.FeeRecipient)
		require.Equal(t, valRegs[i].V1.Message.Pubkey, reg.V1.Message.Pubkey)
		require.Equal(t, valRegs[i].V1.Signature, reg.V1.Signature)
	}
}

// delayer implements scheduler.delayFunc and records the deadline and returns it immediately.
type delayer struct {
	mu        sync.Mutex
	deadlines map[core.Duty]time.Time
}

func (d *delayer) get() map[core.Duty]time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.deadlines
}

// delay implements scheduler.delayFunc and records the deadline and returns it immediately.
func (d *delayer) delay(duty core.Duty, deadline time.Time) <-chan time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.deadlines == nil {
		d.deadlines = make(map[core.Duty]time.Time)
	}

	d.deadlines[duty] = deadline

	resp := make(chan time.Time, 1)
	resp <- deadline

	return resp
}

var _ clockwork.Clock = (*testClock)(nil)

func newTestClock(now time.Time) *testClock {
	return &testClock{
		now:       now,
		callbacks: make(map[time.Time]func()),
	}
}

// testClock implements clockwork.Clock and provides a deterministic mock clock
// that is advanced by calls to Sleep or After.
// Note this *does not* support concurrency.
type testClock struct {
	nowMutex  sync.Mutex
	now       time.Time
	deadline  time.Time // If set, clock won't advance past this time
	callbacks map[time.Time]func()
	paused    atomic.Bool
}

// SetDeadline sets a deadline time that the clock cannot advance past.
// Any Sleep that would advance past the deadline will instead advance to the deadline and pause.
// This is useful for tests that need to prevent background goroutines from advancing time.
func (c *testClock) SetDeadline(deadline time.Time) {
	c.nowMutex.Lock()
	defer c.nowMutex.Unlock()

	c.deadline = deadline
}

// CallbackAfter sets a callback function that is called once
// before Sleep returns at or after the time has been reached.
// It is useful to trigger logic "when a certain time has been reached".
func (c *testClock) CallbackAfter(after time.Time, callback func()) {
	c.callbacks[after] = callback
}

func (c *testClock) After(d time.Duration) <-chan time.Time {
	c.Sleep(d)

	resp := make(chan time.Time, 1)
	resp <- c.Now()

	return resp
}

func (c *testClock) Sleep(d time.Duration) {
	for c.paused.Load() {
		runtime.Gosched()
	}

	c.nowMutex.Lock()
	defer c.nowMutex.Unlock()

	newTime := c.now.Add(d)

	// If deadline is set and we would advance past it, cap at deadline and pause
	if !c.deadline.IsZero() && newTime.After(c.deadline) {
		c.now = c.deadline
		c.paused.Store(true)
	} else {
		c.now = newTime
	}

	for after, callback := range c.callbacks {
		if c.now.Before(after) {
			continue
		}

		callback()
		delete(c.callbacks, after)
	}
}

func (c *testClock) Now() time.Time {
	c.nowMutex.Lock()
	defer c.nowMutex.Unlock()

	now := c.now

	return now
}

func (c *testClock) Since(t time.Time) time.Duration {
	c.nowMutex.Lock()
	defer c.nowMutex.Unlock()

	since := c.now.Sub(t)

	return since
}

func (c *testClock) Pause() {
	c.paused.Store(true)
}

func (c *testClock) Resume() {
	c.paused.Store(false)
}

func (c *testClock) NewTicker(time.Duration) clockwork.Ticker {
	panic("not supported")
}

func (c *testClock) NewTimer(time.Duration) clockwork.Timer {
	panic("not supported")
}

func (c *testClock) AfterFunc(time.Duration, func()) clockwork.Timer {
	panic("not supported")
}

func (c *testClock) Until(t time.Time) time.Duration {
	panic("not supported")
}
