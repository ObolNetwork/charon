// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/state"
	statepb "github.com/obolnetwork/charon/cluster/statepb/v1"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -update

// setIncrementingTime sets the time function to an deterministic incrementing value
// for the duration of the test.
func setIncrementingTime(t *testing.T) {
	t.Helper()

	ts := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	state.SetNowFuncForT(t, func() *timestamppb.Timestamp {
		defer func() {
			ts = ts.Add(time.Minute)
		}()

		return timestamppb.New(ts)
	})
}

func TestNodeApprovals(t *testing.T) {
	setIncrementingTime(t)

	lock, secrets, _ := cluster.NewForT(t, 1, 3, 4, 1)

	parent := testutil.RandomBytes32()

	var approvals []*statepb.SignedMutation
	for _, secret := range secrets {
		approval, err := state.SignNodeApproval(parent, secret)
		require.NoError(t, err)

		approvals = append(approvals, approval)
	}

	composite, err := state.NewNodeApprovalsComposite(approvals)
	testutil.RequireNoError(t, err)

	t.Run("proto", func(t *testing.T) {
		testutil.RequireGoldenProto(t, composite)
	})

	t.Run("unmarshal", func(t *testing.T) {
		b, err := proto.Marshal(composite)
		require.NoError(t, err)
		composite2 := new(statepb.SignedMutation)
		testutil.RequireNoError(t, proto.Unmarshal(b, composite2))
		testutil.RequireProtoEqual(t, composite, composite2)
	})

	t.Run("transform", func(t *testing.T) {
		cluster, err := state.NewClusterFromLock(lock)
		require.NoError(t, err)

		cluster2, err := state.Transform(cluster, composite)
		require.NoError(t, err)

		testutil.RequireProtoEqual(t, cluster, cluster2)
	})
}
