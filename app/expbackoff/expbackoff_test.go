// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package expbackoff_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/expbackoff"
)

func TestConfigs(t *testing.T) {
	tests := []struct {
		name     string
		config   expbackoff.Config
		backoffs []string
		jitter   float64
	}{
		{
			name:   "default",
			config: expbackoff.DefaultConfig,
			jitter: 0.5,
			backoffs: []string{
				"1s",
				"1.6s",
				"2.56s",
				"4.09s",
				"6.55s",
				"10.48s",
				"16.77s",
				"26.84s",
				"42.94s",
				"1m8.71s",
				"1m49.95s",
				"2m0s",
				"2m0s",
			},
		},
		{
			name:   "default max jitter",
			config: expbackoff.DefaultConfig,
			jitter: 1,
			backoffs: []string{
				"1s",
				"1.92s",
				"3.07s",
				"4.91s",
				"7.86s",
				"12.58s",
				"20.13s",
				"32.21s",
				"51.53s",
				"1m22.46s",
				"2m11.94s",
				"2m24s",
				"2m24s",
			},
		},
		{
			name:   "fast",
			config: expbackoff.FastConfig,
			jitter: 0.5,
			backoffs: []string{
				"100ms",
				"160ms",
				"250ms",
				"400ms",
				"650ms",
				"1.04s",
				"1.67s",
				"2.68s",
				"4.29s",
				"5s",
				"5s",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expbackoff.SetRandFloatForT(t, func() float64 {
				return test.jitter
			})

			var resps []string

			for i := range len(test.backoffs) {
				resp := expbackoff.Backoff(test.config, i)
				resps = append(resps, resp.Truncate(time.Millisecond*10).String())
			}

			require.Equal(t, test.backoffs, resps)
		})
	}
}

func TestNewWithReset(t *testing.T) {
	t0 := time.Now()
	now := t0

	expbackoff.SetAfterForT(t, func(d time.Duration) <-chan time.Time {
		now = now.Add(d)

		ch := make(chan time.Time, 1)
		ch <- now

		return ch
	})

	ctx, cancel := context.WithCancel(context.Background())

	backoff, reset := expbackoff.NewWithReset(ctx, expbackoff.WithConfig(expbackoff.Config{
		BaseDelay:  time.Second,
		Multiplier: 2,
		Jitter:     0,
		MaxDelay:   time.Hour,
	}))

	elapsed := func(t *testing.T, expect string) {
		t.Helper()
		require.Equal(t, expect, now.Sub(t0).Truncate(time.Millisecond*10).String())
	}

	backoff()
	elapsed(t, "1s") // +1s
	backoff()
	elapsed(t, "3s") // +2s
	backoff()
	elapsed(t, "7s") // +4s
	backoff()
	elapsed(t, "15s") // +8s

	reset()
	backoff()
	elapsed(t, "16s") // +1s

	cancel()
	backoff()
	elapsed(t, "16s") // +0s
}
