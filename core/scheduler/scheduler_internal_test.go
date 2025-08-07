// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package scheduler

import (
	"context"
	"testing"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

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

func TestResolvingEpoch(t *testing.T) {
	sched, _ := setupScheduler(t)

	sched.setResolvingEpoch(10)
	require.True(t, sched.isResolvingEpoch(10))
	require.False(t, sched.isResolvingEpoch(11))

	sched.setResolvingEpoch(11)
	require.False(t, sched.isResolvingEpoch(10))
	require.True(t, sched.isResolvingEpoch(11))
}
