// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMarkParticipated(t *testing.T) {
	io := newInstanceIO[qbftMsg]()

	// First call succeeds.
	err := io.MarkParticipated()
	require.NoError(t, err)

	// Second call fails.
	err = io.MarkParticipated()
	require.ErrorContains(t, err, "already participated")
}

func TestMarkProposed(t *testing.T) {
	io := newInstanceIO[qbftMsg]()

	// First call succeeds.
	err := io.MarkProposed()
	require.NoError(t, err)

	// Second call fails.
	err = io.MarkProposed()
	require.ErrorContains(t, err, "already proposed")
}

func TestMaybeStart(t *testing.T) {
	io := newInstanceIO[qbftMsg]()

	// First call succeeds.
	ok := io.MaybeStart()
	require.True(t, ok)

	// Second call fails.
	ok = io.MaybeStart()
	require.False(t, ok)
}
