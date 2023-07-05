// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
)

func TestVerifyLock(t *testing.T) {
	b, err := os.ReadFile("/Users/corver/Downloads/cluster-lock (1).json")
	require.NoError(t, err)

	var lock cluster.Lock
	err = json.Unmarshal(b, &lock)
	require.NoError(t, err)

	require.NoError(t, lock.VerifyHashes())
	require.NoError(t, lock.VerifySignatures())
}
