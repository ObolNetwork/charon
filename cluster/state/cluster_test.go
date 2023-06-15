// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/state"
	pbv1 "github.com/obolnetwork/charon/cluster/statepb/v1"
	"github.com/obolnetwork/charon/testutil"
)

func TestDuplicateENRs(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 1, 3, 4, 0)

	_, err := state.Cluster{Operators: []*pbv1.Operator{
		{Enr: lock.Operators[0].ENR},
		{Enr: lock.Operators[0].ENR},
	}}.Peers()
	require.ErrorContains(t, err, "duplicate peer enrs")
}

// RequireGoldenCluster is a custom golden file function for Cluster
// since it contains a mix of proto and non-proto fields.
func RequireGoldenCluster(t *testing.T, cluster state.Cluster, opts ...func(*string)) {
	t.Helper()
	testutil.RequireGoldenBytes(t, serialiseCluster(t, cluster), opts...)
}

// RequireClusterEqual is a custom equality function for Cluster
// since it contains a mix of proto and non-proto fields.
func RequireClusterEqual(t *testing.T, a, b state.Cluster) {
	t.Helper()
	require.Equal(t, serialiseCluster(t, a), serialiseCluster(t, b))
}

func serialiseCluster(t *testing.T, cluster state.Cluster) []byte {
	t.Helper()
	fields := map[string]string{
		"Hash":         fmt.Sprintf("%x", cluster.Hash),
		"Name":         cluster.Name,
		"Threshold":    fmt.Sprintf("%d", cluster.Threshold),
		"DKGAlgorithm": cluster.DKGAlgorithm,
		"ForkVersion":  fmt.Sprintf("%x", cluster.ForkVersion),
		"Operators":    protosToText(cluster.Operators),
		"Validators":   protosToText(cluster.Validators),
	}

	b, err := json.MarshalIndent(fields, "", "  ")
	require.NoError(t, err)

	return b
}

func protosToText[P proto.Message](protos []P) string {
	var resp []string
	for _, p := range protos {
		resp = append(resp, prototext.Format(p))
	}

	return strings.Join(resp, ",")
}
