// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/obolnetwork/charon/app/log"
)

func TestNewLogger(t *testing.T) {
	var buf zaptest.Buffer

	log.InitConsoleForT(t, &buf)

	ctx := t.Context()
	logger := newLogger(ctx)
	require.Equal(t, logger.logCtx, ctx)

	logger.Error(ctx, "test error log", errors.New("some error"))
	logger.Info(ctx, "test info log")

	logs := buf.String()
	require.Contains(t, logs, "test error log")
	require.Contains(t, logs, "some error")
	require.Contains(t, logs, "test info log")
}
