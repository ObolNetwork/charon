// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package utils_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	cqbft "github.com/obolnetwork/charon/core/consensus/qbft"
	"github.com/obolnetwork/charon/core/consensus/utils"
)

func TestMarkParticipated(t *testing.T) {
	io := utils.NewInstanceIO[cqbft.Msg]()

	// First call succeeds.
	err := io.MarkParticipated()
	require.NoError(t, err)

	// Second call fails.
	err = io.MarkParticipated()
	require.ErrorContains(t, err, "already participated")
}

func TestMarkProposed(t *testing.T) {
	io := utils.NewInstanceIO[cqbft.Msg]()

	// First call succeeds.
	err := io.MarkProposed()
	require.NoError(t, err)

	// Second call fails.
	err = io.MarkProposed()
	require.ErrorContains(t, err, "already proposed")
}

func TestMaybeStart(t *testing.T) {
	io := utils.NewInstanceIO[cqbft.Msg]()

	// First call succeeds.
	ok := io.MaybeStart()
	require.True(t, ok)

	// Second call fails.
	ok = io.MaybeStart()
	require.False(t, ok)
}
