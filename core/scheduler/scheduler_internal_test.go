// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package scheduler

import (
	"context"
	"testing"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestDelaySlotOffset(t *testing.T) {
	slot := core.Slot{Slot: 100, Time: time.Now(), SlotDuration: 12 * time.Second}

	tests := []struct {
		name        string
		offset      time.Duration
		expectDelay bool
	}{
		{
			name:        "duty with a deadline is delayed to its offset",
			offset:      3 * time.Second, // Attestations are due 1/4 into the slot from the gloas fork.
			expectDelay: true,
		},
		{
			name:        "duty without a deadline is triggered at the start of the slot",
			offset:      0,
			expectDelay: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var delayed []time.Time

			delayFunc := func(_ core.Duty, deadline time.Time) <-chan time.Time {
				delayed = append(delayed, deadline)

				resp := make(chan time.Time, 1)
				resp <- deadline

				return resp
			}

			require.True(t, delaySlotOffset(t.Context(), slot, core.NewAttesterDuty(slot.Slot), delayFunc, test.offset))

			if !test.expectDelay {
				require.Empty(t, delayed)

				return
			}

			require.Equal(t, []time.Time{slot.Time.Add(test.offset)}, delayed)
		})
	}
}

func setupScheduler(t *testing.T) (*Scheduler, validators) {
	t.Helper()

	var (
		ctx    = context.Background()
		t0     time.Time
		valSet = beaconmock.ValidatorSetA
	)

	// Configure beacon mock.
	eth2Cl, err := beaconmock.New(
		t.Context(),
		beaconmock.WithValidatorSet(valSet),
		beaconmock.WithGenesisTime(t0),
		beaconmock.WithDeterministicAttesterDuties(0),
		beaconmock.WithDeterministicProposerDuties(0),
		beaconmock.WithDeterministicSyncCommDuties(2, 2),
		beaconmock.WithSlotsPerEpoch(1),
	)

	require.NoError(t, err)

	// Randomize duty pubkeys
	oldAttesterFunc := eth2Cl.AttesterDutiesFunc
	oldSyncFunc := eth2Cl.SyncCommitteeDutiesFunc
	oldProposerFunc := eth2Cl.ProposerDutiesFunc

	eth2Cl.AttesterDutiesFunc = func(ctx context.Context, epoch eth2p0.Epoch, indices []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
		res, err := oldAttesterFunc(ctx, epoch, indices)
		if err != nil {
			return nil, err
		}

		for idx := range len(res) {
			res[idx].PubKey = testutil.RandomEth2PubKey(t)
		}

		return res, nil
	}

	eth2Cl.CachedAttesterDutiesFunc = func(ctx context.Context, epoch eth2p0.Epoch, indices []eth2p0.ValidatorIndex) (eth2wrap.AttesterDutyWithMeta, error) {
		res, err := oldAttesterFunc(ctx, epoch, indices)
		if err != nil {
			return eth2wrap.AttesterDutyWithMeta{}, err
		}

		for idx := range len(res) {
			res[idx].PubKey = testutil.RandomEth2PubKey(t)
		}

		return eth2wrap.AttesterDutyWithMeta{Duties: res, Metadata: nil}, nil
	}

	eth2Cl.SyncCommitteeDutiesFunc = func(ctx context.Context, epoch eth2p0.Epoch, validatorIndices []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error) {
		res, err := oldSyncFunc(ctx, epoch, validatorIndices)
		if err != nil {
			return nil, err
		}

		for idx := range len(res) {
			res[idx].PubKey = testutil.RandomEth2PubKey(t)
		}

		return res, nil
	}

	eth2Cl.CachedSyncCommDutiesFunc = func(ctx context.Context, epoch eth2p0.Epoch, validatorIndices []eth2p0.ValidatorIndex) (eth2wrap.SyncDutyWithMeta, error) {
		res, err := oldSyncFunc(ctx, epoch, validatorIndices)
		if err != nil {
			return eth2wrap.SyncDutyWithMeta{}, err
		}

		for idx := range len(res) {
			res[idx].PubKey = testutil.RandomEth2PubKey(t)
		}

		return eth2wrap.SyncDutyWithMeta{Duties: res, Metadata: nil}, nil
	}

	eth2Cl.ProposerDutiesFunc = func(ctx context.Context, epoch eth2p0.Epoch, indices []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
		res, err := oldProposerFunc(ctx, epoch, indices)
		if err != nil {
			return nil, err
		}

		for idx := range len(res) {
			res[idx].PubKey = testutil.RandomEth2PubKey(t)
		}

		return res, nil
	}

	eth2Cl.CachedProposerDutiesFunc = func(ctx context.Context, epoch eth2p0.Epoch, indices []eth2p0.ValidatorIndex) (eth2wrap.ProposerDutyWithMeta, error) {
		res, err := oldProposerFunc(ctx, epoch, indices)
		if err != nil {
			return eth2wrap.ProposerDutyWithMeta{}, err
		}

		for idx := range len(res) {
			res[idx].PubKey = testutil.RandomEth2PubKey(t)
		}

		return eth2wrap.ProposerDutyWithMeta{Duties: res, Metadata: nil}, nil
	}

	var schedVals validators

	for _, v := range valSet {
		pk, err := v.PubKey(ctx)
		require.NoError(t, err)

		schedVals = append(schedVals, validator{
			PubKey: core.PubKeyFrom48Bytes(pk),
			VIdx:   v.Index,
		})
	}

	forkSchedule, err := eth2wrap.FetchForkConfig(ctx, eth2Cl)
	require.NoError(t, err)

	sched := &Scheduler{
		eth2Cl:         eth2Cl,
		forkSchedule:   func() eth2wrap.ForkForkSchedule { return forkSchedule },
		builderEnabled: false,
	}

	return sched, schedVals
}

// TestTriggerOffset asserts that gloas attester duties are triggered at the start of the slot and
// payload attestation duties once the payload is due, ahead of their own due times, while other
// duties are triggered at their slot offset.
func TestTriggerOffset(t *testing.T) {
	const gloasEpoch = 2

	offsets := map[core.DutyType]time.Duration{
		core.DutyAttester:                 3 * time.Second,
		core.DutyExecutionPayloadEnvelope: 6 * time.Second,
		core.DutyPayloadAttestation:       9 * time.Second,
	}

	sched := &Scheduler{
		slotOffsetFunc: func(duty core.Duty) time.Duration { return offsets[duty.Type] },
		forkSchedule: func() eth2wrap.ForkForkSchedule {
			return eth2wrap.ForkForkSchedule{eth2wrap.Gloas: {Epoch: gloasEpoch}}
		},
	}

	preGloas := core.Slot{Slot: 1, SlotsPerEpoch: 32}
	gloas := core.Slot{Slot: gloasEpoch * 32, SlotsPerEpoch: 32}

	require.Equal(t, 3*time.Second, sched.triggerOffset(preGloas, core.NewAttesterDuty(preGloas.Slot)))
	require.Equal(t, time.Duration(0), sched.triggerOffset(gloas, core.NewAttesterDuty(gloas.Slot)))
	require.Equal(t, 6*time.Second, sched.triggerOffset(gloas, core.NewPayloadAttestationDuty(gloas.Slot)))
	require.Equal(t, 6*time.Second, sched.triggerOffset(gloas, core.Duty{Slot: gloas.Slot, Type: core.DutyExecutionPayloadEnvelope}))
}

func TestResolveAttDuties(t *testing.T) {
	sched, schedVals := setupScheduler(t)

	require.ErrorContains(t, sched.resolveAttDuties(context.Background(), core.Slot{
		SlotDuration:  1 * time.Second,
		SlotsPerEpoch: 1,
	}, schedVals), "invalid attester duty pubkey")
}

func TestResolveProdDuties(t *testing.T) {
	sched, schedVals := setupScheduler(t)

	require.ErrorContains(t, sched.resolveProDuties(context.Background(), core.Slot{
		SlotDuration:  1 * time.Second,
		SlotsPerEpoch: 1,
	}, schedVals), "invalid proposer duty pubkey")
}

func TestResolveSyncCommDuties(t *testing.T) {
	sched, schedVals := setupScheduler(t)

	require.ErrorContains(t, sched.resolveSyncCommDuties(context.Background(), core.Slot{
		SlotDuration:  1 * time.Second,
		SlotsPerEpoch: 1,
	}, schedVals), "invalid sync committee duty pubkey")
}

func TestResolveValidators(t *testing.T) {
	ctx := context.Background()

	// beaconmock's EPOCHS_PER_SYNC_COMMITTEE_PERIOD is 256, so epoch 600 is in period 2.
	const epoch = 600

	mkVal := func(index eth2p0.ValidatorIndex, status eth2v1.ValidatorState, exitEpoch eth2p0.Epoch) *eth2v1.Validator {
		return &eth2v1.Validator{
			Index:   index,
			Balance: 1,
			Status:  status,
			Validator: &eth2p0.Validator{
				PublicKey:       testutil.RandomEth2PubKey(t),
				ActivationEpoch: 2, // != epoch
				ExitEpoch:       exitEpoch,
			},
		}
	}

	complete := eth2wrap.CompleteValidators{
		1: mkVal(1, eth2v1.ValidatorStateActiveOngoing, 1<<63),    // active (exit epoch far future)
		2: mkVal(2, eth2v1.ValidatorStateExitedUnslashed, 520),    // exited this period (2)
		3: mkVal(3, eth2v1.ValidatorStateExitedSlashed, 300),      // exited previous period (1)
		4: mkVal(4, eth2v1.ValidatorStateWithdrawalPossible, 100), // exited two periods ago (0)
		5: mkVal(5, eth2v1.ValidatorStatePendingQueued, 1<<63),    // never activated
		// Exited previous period (1) and already withdrawable: on mainnet the withdrawability
		// delay equals one sync period, so a validator reliably reaches withdrawal_possible while
		// still serving its final committee period. Must be included via HasExited, not IsExited.
		6: mkVal(6, eth2v1.ValidatorStateWithdrawalPossible, 300),
	}

	eth2Cl, err := beaconmock.New(t.Context())
	require.NoError(t, err)

	eth2Cl.CachedValidatorsFunc = func(context.Context) (eth2wrap.ActiveValidators, eth2wrap.CompleteValidators, error) {
		return nil, complete, nil
	}

	noop := func(core.PubKey, eth2p0.Gwei, string) {}

	active, syncComm, err := resolveValidators(ctx, eth2Cl, noop, epoch)
	require.NoError(t, err)

	// Attestation/proposal duties only apply to active validators.
	require.Equal(t, []eth2p0.ValidatorIndex{1}, active.Indexes())

	// Sync committee duties additionally cover validators that exited in the current or previous
	// period (2, 3 and 6, the latter already withdrawable), since membership can persist that long.
	// A validator that exited two periods ago (4) and one that never activated (5) are excluded.
	require.ElementsMatch(t, []eth2p0.ValidatorIndex{1, 2, 3, 6}, syncComm.Indexes())
}

func TestResolvingEpoch(t *testing.T) {
	sched, _ := setupScheduler(t)

	sched.setResolvingEpoch(10)
	require.True(t, sched.isResolvingEpoch(10))
	require.False(t, sched.isResolvingEpoch(11))

	sched.setResolvingEpoch(11)
	require.False(t, sched.isResolvingEpoch(10))
	require.True(t, sched.isResolvingEpoch(11))
}

func TestReachedGloasFork(t *testing.T) {
	var t0 time.Time

	tests := []struct {
		name string
		opts []beaconmock.Option
		want bool
	}{
		{
			name: "gloas not scheduled",
			want: false,
		},
		{
			name: "gloas fork in the future",
			opts: []beaconmock.Option{
				beaconmock.WithSpecOverride("GLOAS_FORK_VERSION", "0x07000000"),
				beaconmock.WithSpecOverride("GLOAS_FORK_EPOCH", "100"),
			},
			want: false,
		},
		{
			name: "gloas fork active from genesis",
			opts: []beaconmock.Option{
				beaconmock.WithSpecOverride("GLOAS_FORK_VERSION", "0x07000000"),
				beaconmock.WithSpecOverride("GLOAS_FORK_EPOCH", "0"),
			},
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := append([]beaconmock.Option{beaconmock.WithGenesisTime(t0)}, test.opts...)

			eth2Cl, err := beaconmock.New(t.Context(), opts...)
			require.NoError(t, err)

			forkSchedule, err := eth2wrap.FetchForkConfig(t.Context(), eth2Cl)
			require.NoError(t, err)

			sched := &Scheduler{eth2Cl: eth2Cl, clock: clockwork.NewFakeClockAt(t0), forkSchedule: func() eth2wrap.ForkForkSchedule { return forkSchedule }}

			require.Equal(t, test.want, sched.reachedGloasFork(t.Context()))
		})
	}
}

func TestHandleHeadEventGloas(t *testing.T) {
	featureset.EnableForT(t, featureset.FetchAttOnBlock)

	tests := []struct {
		name          string
		gloasEpoch    string
		wantFetchOnly bool
	}{
		{
			name:          "pre-gloas head events prefetch attestation data",
			gloasEpoch:    "100",
			wantFetchOnly: true,
		},
		{
			name:          "gloas head events are left to the fetcher",
			gloasEpoch:    "0",
			wantFetchOnly: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			eth2Cl, err := beaconmock.New(t.Context(),
				beaconmock.WithSpecOverride("GLOAS_FORK_VERSION", "0x07000000"),
				beaconmock.WithSpecOverride("GLOAS_FORK_EPOCH", test.gloasEpoch),
			)
			require.NoError(t, err)

			forkSchedule, err := eth2wrap.FetchForkConfig(t.Context(), eth2Cl)
			require.NoError(t, err)

			const slot = 1

			duty := core.NewAttesterDuty(slot)
			sched := &Scheduler{
				eth2Cl:       eth2Cl,
				forkSchedule: func() eth2wrap.ForkForkSchedule { return forkSchedule },
				duties: map[core.Duty]core.DutyDefinitionSet{
					duty: {testutil.RandomCorePubKey(t): core.NewAttesterDefinition(&eth2v1.AttesterDuty{Slot: slot, CommitteeLength: 1, CommitteesAtSlot: 1})},
				},
			}

			fetched := make(chan core.Duty, 1)

			sched.RegisterFetcherFetchOnly(func(_ context.Context, duty core.Duty, _ core.DutyDefinitionSet, _ string, _ eth2p0.Root) error {
				fetched <- duty
				return nil
			})

			sched.HandleHeadEvent(t.Context(), slot, testutil.RandomRoot(), "bn")

			_, triggered := sched.eventTriggeredAttestations.Load(uint64(slot))
			require.Equal(t, test.wantFetchOnly, triggered)

			if test.wantFetchOnly {
				select {
				case got := <-fetched:
					require.Equal(t, duty, got)
				case <-time.After(time.Second):
					require.Fail(t, "early attestation data fetch not triggered")
				}
			}
		})
	}
}

// TestResolveProDutiesVersion verifies that proposer duties are resolved via v1 before the gloas fork and
// via v2 from it, since v2 is only served by gloas-ready beacon nodes.
func TestResolveProDutiesVersion(t *testing.T) {
	var t0 time.Time

	eth2Cl, err := beaconmock.New(
		t.Context(),
		beaconmock.WithValidatorSet(beaconmock.ValidatorSetA),
		beaconmock.WithGenesisTime(t0),
		beaconmock.WithDeterministicAttesterDuties(0),
		beaconmock.WithDeterministicProposerDuties(0),
		beaconmock.WithDeterministicSyncCommDuties(2, 2),
		beaconmock.WithSlotsPerEpoch(1),
		beaconmock.WithSpecOverride("GLOAS_FORK_VERSION", "0x07000000"),
		beaconmock.WithSpecOverride("GLOAS_FORK_EPOCH", "2"),
	)
	require.NoError(t, err)

	var v1Epochs, v2Epochs []eth2p0.Epoch

	v1Func, v2Func := eth2Cl.CachedProposerDutiesFunc, eth2Cl.CachedProposerDutiesV2Func
	eth2Cl.CachedProposerDutiesFunc = func(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) (eth2wrap.ProposerDutyWithMeta, error) {
		v1Epochs = append(v1Epochs, epoch)

		return v1Func(ctx, epoch, vidxs)
	}
	eth2Cl.CachedProposerDutiesV2Func = func(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) (eth2wrap.ProposerDutyWithMeta, error) {
		v2Epochs = append(v2Epochs, epoch)

		return v2Func(ctx, epoch, vidxs)
	}

	forkSchedule, err := eth2wrap.FetchForkConfig(t.Context(), eth2Cl)
	require.NoError(t, err)

	sched, err := New(t.Context(), nil, eth2Cl, func() eth2wrap.ForkForkSchedule { return forkSchedule }, false)
	require.NoError(t, err)

	for epoch := range uint64(3) {
		slot := core.Slot{Slot: epoch, Time: t0.Add(time.Duration(epoch) * time.Second), SlotDuration: time.Second, SlotsPerEpoch: 1}
		require.NoError(t, sched.resolveDuties(t.Context(), slot))
	}

	require.Equal(t, []eth2p0.Epoch{0, 1}, v1Epochs)
	require.Equal(t, []eth2p0.Epoch{2}, v2Epochs)
}
