// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package manifest_test

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
)

const (
	v1_10 = "v1.10.0"
	v1_9  = "v1.9.0"
	v1_8  = "v1.8.0"
	v1_7  = "v1.7.0"
	v1_6  = "v1.6.0"
	v1_5  = "v1.5.0"
	v1_4  = "v1.4.0"
	v1_3  = "v1.3.0"
	v1_2  = "v1.2.0"
	v1_1  = "v1.1.0"
	v1_0  = "v1.0.0"
)

func isAnyVersion(version string, list ...string) bool {
	for _, v := range list {
		if version == v {
			return true
		}
	}

	return false
}

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
