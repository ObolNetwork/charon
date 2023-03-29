// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package testutil

import (
	"context"
	"testing"
	"time"
)

// EnsureCleanup calls cleanupFunc in one of two cases:
//   - 100ms before the test deadline is exceeded when it is run with `-timeout`, or
//   - on test cleanup
func EnsureCleanup(t *testing.T, cleanupFunc func()) {
	t.Helper()
	testDeadline, present := t.Deadline()
	if !present {
		t.Cleanup(cleanupFunc)
		return
	}

	ctx := context.Background()

	// Adapted from https://github.com/golang/go/issues/24050#issuecomment-1137682781
	testDeadline = testDeadline.Add(-100 * time.Millisecond)
	dctx, cancel := context.WithDeadline(ctx, testDeadline)
	go func() {
		<-dctx.Done()
		cancel()
		cleanupFunc()
	}()
}
