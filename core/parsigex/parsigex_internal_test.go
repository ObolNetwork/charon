// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package parsigex

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/testutil"
)

// newTestMsg returns a parsigex message for the duty containing numEntries partial signatures.
func newTestMsg(t *testing.T, duty core.Duty, numEntries int) *pbv1.ParSigExMsg {
	t.Helper()

	newData := func() core.ParSignedData {
		if duty.Type == core.DutyExit {
			return core.NewPartialSignedVoluntaryExit(testutil.RandomExit(), 1)
		}

		return core.NewPartialSignedRandao(123, testutil.RandomEth2Signature(), 1)
	}

	set := make(core.ParSignedDataSet)
	for range numEntries {
		set[testutil.RandomCorePubKey(t)] = newData()
	}

	require.Len(t, set, numEntries)

	setPb, err := core.ParSignedDataSetToProto(set)
	require.NoError(t, err)

	return &pbv1.ParSigExMsg{
		Duty:    core.DutyToProto(duty),
		DataSet: setPb,
	}
}

// newTestParSigEx returns a ParSigEx and a pointer to the number of verifyFunc calls it made.
func newTestParSigEx(maxSetSize int, deadlineFunc core.DeadlineFunc) (*ParSigEx, *int) {
	var verifyCalls int

	return &ParSigEx{
		verifyFunc: func(context.Context, peer.ID, core.Duty, core.PubKey, core.ParSignedData) error {
			verifyCalls++
			return nil
		},
		gaterFunc:    func(core.Duty) bool { return true },
		maxSetSize:   maxSetSize,
		deadlineFunc: deadlineFunc,
	}, &verifyCalls
}

func TestHandleDropsExpiredDuty(t *testing.T) {
	expiredDuty := core.Duty{Slot: 1, Type: core.DutyRandao}

	// Deadline for the duty has already passed.
	deadlineFunc := func(core.Duty) (time.Time, bool) {
		return time.Now().Add(-time.Hour), true
	}

	parSigEx, verifyCalls := newTestParSigEx(10, deadlineFunc)

	_, _, err := parSigEx.handle(context.Background(), "", newTestMsg(t, expiredDuty, 1))
	require.ErrorContains(t, err, "duty deadline expired")
	require.Zero(t, *verifyCalls, "expired duty must be dropped before signature verification")
}

func TestHandleAllowsExemptDuty(t *testing.T) {
	// Exits and builder registrations never expire, so they must be processed
	// regardless of how old their slot is.
	exemptDuty := core.Duty{Slot: 1, Type: core.DutyExit}

	deadlineFunc := func(core.Duty) (time.Time, bool) {
		return time.Time{}, false // Never expires.
	}

	parSigEx, verifyCalls := newTestParSigEx(10, deadlineFunc)

	_, _, err := parSigEx.handle(context.Background(), "", newTestMsg(t, exemptDuty, 1))
	require.NoError(t, err)
	require.Equal(t, 1, *verifyCalls)
}

func TestHandleDropsOversizedSet(t *testing.T) {
	duty := core.Duty{Slot: 1, Type: core.DutyRandao}

	deadlineFunc := func(core.Duty) (time.Time, bool) {
		return time.Now().Add(time.Hour), true
	}

	const maxSetSize = 4

	parSigEx, verifyCalls := newTestParSigEx(maxSetSize, deadlineFunc)

	_, _, err := parSigEx.handle(context.Background(), "", newTestMsg(t, duty, maxSetSize+1))
	require.ErrorContains(t, err, "partial signature set too large")
	require.Zero(t, *verifyCalls, "oversized set must be dropped before signature verification")

	// A set at the limit is still processed.
	_, _, err = parSigEx.handle(context.Background(), "", newTestMsg(t, duty, maxSetSize))
	require.NoError(t, err)
	require.Equal(t, maxSetSize, *verifyCalls)
}
