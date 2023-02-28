// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package testutil

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/log"
)

// RequireNoError extends require.NoError with additional error stack trace and
// structured field logging for improved test debugging.
func RequireNoError(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		return
	}

	log.Error(context.Background(), "Unexpected test error", err)
	require.NoErrorf(t, err, "See error log above for more info")
}
