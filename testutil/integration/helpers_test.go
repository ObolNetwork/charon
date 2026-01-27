// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package integration_test

import (
	"context"
	"flag"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

var integration = flag.Bool("integration", false, "Enable this package's integration tests")

func skipIfDisabled(t *testing.T) {
	t.Helper()

	if !*integration {
		t.Skip("Integration tests are disabled")
	}
}

// asserter provides an abstract callback asserter.
type asserter struct {
	Timeout   time.Duration
	callbacks sync.Map // map[string]bool
}

// Await waits for all nodes to ping each other or time out.
func (a *asserter) await(ctx context.Context, t *testing.T, expect int) error {
	t.Helper()

	var actual map[any]bool

	ok := assert.Eventually(t, func() bool {
		if ctx.Err() != nil {
			return true
		}

		actual = make(map[any]bool)

		a.callbacks.Range(func(k, v any) bool {
			actual[k] = true

			return true
		})

		return len(actual) >= expect
	}, a.Timeout, time.Millisecond*10)

	if ctx.Err() != nil {
		return context.Canceled
	}

	if !ok {
		return errors.New(fmt.Sprintf("Timeout waiting for callbacks, expect=%d, actual=%d: %v", expect, len(actual), actual))
	}

	return nil
}

func peerCtx(ctx context.Context, idx int) context.Context {
	return log.WithCtx(ctx, z.Int("peer_index", idx))
}
