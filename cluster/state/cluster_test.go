// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/state"
)

func TestDuplicateENRs(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 1, 3, 4, 0)

	_, err := state.Cluster{Operators: []state.Operator{
		{ENR: lock.Operators[0].ENR},
		{ENR: lock.Operators[0].ENR},
	}}.Peers()
	require.ErrorContains(t, err, "duplicate peer enrs")
}
