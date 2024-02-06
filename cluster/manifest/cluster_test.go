// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package manifest_test

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
)

func TestDuplicateENRs(t *testing.T) {
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := cluster.NewForT(t, 1, 3, 4, seed, random)

	_, err := manifest.ClusterPeers(&manifestpb.Cluster{Operators: []*manifestpb.Operator{
		{Enr: lock.Operators[0].ENR},
		{Enr: lock.Operators[0].ENR},
	}})
	require.ErrorContains(t, err, "duplicate peer enrs")
}
