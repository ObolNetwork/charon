// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package retry_test

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/retry"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestRetryer(t *testing.T) {
	tests := []struct {
		Name           string
		Func           func(ctx context.Context, attempt int) error
		TimeoutCount   int
		ExpectBackoffs int
	}{
		{
			Name:           "no retries",
			Func:           func(ctx context.Context, attempt int) error { return nil },
			ExpectBackoffs: 0,
		},
		{
			Name: "one retry on ctx cancelled",
			Func: func(ctx context.Context, attempt int) error {
				if attempt == 0 {
					return context.Canceled
				}
				return nil //nolint:nlreturn
			},
			ExpectBackoffs: 1,
		},
		{
			Name: "not retryable error",
			Func: func(ctx context.Context, attempt int) error {
				return errors.New("some error")
			},
			ExpectBackoffs: 0,
		},
		{
			Name: "5 retries ",
			Func: func(ctx context.Context, attempt int) error {
				if attempt < 5 {
					return context.Canceled
				}
				return nil //nolint:nlreturn
			},
			ExpectBackoffs: 5,
		},
		{
			Name: "timeout after 1 retry ",
			Func: func(ctx context.Context, attempt int) error {
				if attempt == 0 {
					return context.Canceled
				}
				return nil //nolint:nlreturn
			},
			TimeoutCount:   1,
			ExpectBackoffs: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			ctxTimeoutFunc := func(ctx context.Context, slot int64) (context.Context, context.CancelFunc) {
				return ctx, cancel
			}

			var backoffCount int
			backoffProvider := func() func() <-chan time.Time {
				return func() <-chan time.Time {
					backoffCount++
					if backoffCount >= test.TimeoutCount {
						cancel()
					}

					return time.After(0)
				}
			}

			retryer, err := retry.NewForT(t, ctxTimeoutFunc, backoffProvider)
			require.NoError(t, err)

			var attempt int
			retryer.DoAsync(ctx, 999, "test", func(ctx context.Context) error {
				defer func() { attempt++ }()
				return test.Func(ctx, attempt)
			})

			require.Equal(t, test.ExpectBackoffs, backoffCount)
		})
	}
}

//go:generate go test . -v -run=TestShutdown -count=10

func TestShutdown(t *testing.T) {
	ctx := context.Background()
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	retryer, err := retry.New(ctx, bmock)
	require.NoError(t, err)

	const n = 3
	waiting := make(chan struct{}, n)
	stop := make(chan struct{})
	done := make(chan struct{})

	// Start 3 long-running functions
	for i := 0; i < 3; i++ {
		go retryer.DoAsync(ctx, 999999, "test", func(_ context.Context) error {
			waiting <- struct{}{}
			<-stop

			return context.Canceled
		})
	}

	// Wait for functions to block
	for i := 0; i < n; i++ {
		<-waiting
	}

	// Trigger shutdown
	go func() {
		retryer.Shutdown(ctx)
		close(done)
	}()

	runtime.Gosched()

	// Ensure Shutdown is blocking
	select {
	case <-done:
		require.Fail(t, "shutdown not blocking")
	default:
	}

	close(stop)
	<-done
}
