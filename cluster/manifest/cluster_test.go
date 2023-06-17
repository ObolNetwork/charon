// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package manifest_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
)

func TestDuplicateENRs(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 1, 3, 4, 0)

	_, err := manifest.ClusterPeers(&manifestpb.Cluster{Operators: []*manifestpb.Operator{
		{Enr: lock.Operators[0].ENR},
		{Enr: lock.Operators[0].ENR},
	}})
	require.ErrorContains(t, err, "duplicate peer enrs")
}
