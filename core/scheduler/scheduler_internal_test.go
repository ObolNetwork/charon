// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package scheduler

import (
	"context"
	"testing"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

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

	sched := &Scheduler{
		eth2Cl:         eth2Cl,
		builderEnabled: false,
	}

	return sched, schedVals
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
