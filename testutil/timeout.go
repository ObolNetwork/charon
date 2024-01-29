// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package testutil

import (
	"sync"
	"testing"
	"time"
)

// EnsureCleanup calls cleanupFunc in one of two cases:
//   - 100ms before the test deadline is exceeded when it is run with `-timeout`, or
//   - on test cleanup
func EnsureCleanup(t *testing.T, cleanupFunc func()) {
	t.Helper()

	var cfOnce sync.Once

	t.Cleanup(func() {
		cfOnce.Do(cleanupFunc)
	})

	testDeadline, present := t.Deadline()
	if !present {
		return
	}

	// Adapted from https://github.com/golang/go/issues/24050#issuecomment-1137682781
	go func() {
		time.Sleep(time.Until(testDeadline.Add(-100 * time.Millisecond)))
		cfOnce.Do(cleanupFunc)
	}()
}
