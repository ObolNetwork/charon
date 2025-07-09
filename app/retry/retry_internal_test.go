// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package retry

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/expbackoff"
)

func TestDelayForIteration(t *testing.T) {
	for i := 0; i < 13; i++ {
		delay := delayForIteration(i)
		t.Log(delay)

		backoff := expbackoff.Backoff(backoffConfig, i)
		deltaWithJitter := float64(backoff) * (1 + backoffConfig.Jitter)
		require.InDelta(t, backoff, delay, deltaWithJitter)
	}
}
