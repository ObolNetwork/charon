// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
)

func TestNewCluster(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 3, 3, 3, 0)
	require.NoError(t, lock.VerifyHashes())
	require.NoError(t, lock.VerifySignatures())
}
