// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core/hotstuff"
)

func TestBlacklist(t *testing.T) {
	b := hotstuff.NewBlacklist()

	b.Add(7)

	require.True(t, b.Contains(7))
	require.False(t, b.Contains(6))

	b.Add(9)
	b.Remove(7)

	require.False(t, b.Contains(7))
	require.True(t, b.Contains(9))
}
