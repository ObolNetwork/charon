// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
)

func TestLoadClusterLock(t *testing.T) {
	ctx := t.Context()

	// Load the test lock file with noVerify=true to skip signature verification
	lock, err := cluster.LoadClusterLock(ctx, "testdata/cluster_lock_v1_10_0.json", true, nil)
	require.NoError(t, err)
	require.NotNil(t, lock)

	// Verify basic fields from the test file
	require.Equal(t, "test definition", lock.Name)
	require.Equal(t, "v1.10.0", lock.Version)
	require.Equal(t, "0194FDC2-FA2F-4CC0-81D3-FF12045B73C8", lock.UUID)
	require.Equal(t, 2, lock.NumValidators)
	require.Equal(t, 3, lock.Threshold)
	require.Len(t, lock.Operators, 2)
	require.Len(t, lock.Validators, 2)

	// Verify first operator
	require.Equal(t, "0xe0255aa5b7d44bec40f84c892b9bffd43629b022", lock.Operators[0].Address)
	require.Contains(t, lock.Operators[0].ENR, "enr:-HW4QODeB3AVJFkDYomS49MS5zbgdawwMP9X9jdldV3DeNiDCnYxAQVQ-DXcZYzu7Qk0AjXaWMdpykStZDy035vViLWAgmlkgnY0iXNlY3AyNTZrMaECJ-LHSLqRGKa3j7oOwpC2TjLLOBtKYEKxUZEkAw3bUac")

	// Verify first distributed validator
	require.Equal(t, "0x6865fcf92b0c3a17c9028be9914eb7649c6c9347800979d1830356f2a54c3deab2a4b4475d63afbe8fb56987c77f5818", lock.Validators[0].PublicKeyHex())
	require.Len(t, lock.Validators[0].PubShares, 2)
}
