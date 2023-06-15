// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/state"
	statepb "github.com/obolnetwork/charon/cluster/statepb/v1"
)

func TestDuplicateENRs(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 1, 3, 4, 0)

	_, err := state.ClusterPeers(&statepb.Cluster{Operators: []*statepb.Operator{
		{Enr: lock.Operators[0].ENR},
		{Enr: lock.Operators[0].ENR},
	}})
	require.ErrorContains(t, err, "duplicate peer enrs")
}
