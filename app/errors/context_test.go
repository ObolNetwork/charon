// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package errors_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
)

func TestWithCtxErr(t *testing.T) {
	msg := "wrap"

	ctx, cancel := context.WithCancel(context.Background())
	ctx = errors.WithCtxErr(ctx, msg)

	cancel()
	require.Contains(t, ctx.Err().Error(), msg)
	require.ErrorIs(t, ctx.Err(), context.Canceled)
}
