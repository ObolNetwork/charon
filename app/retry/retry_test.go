// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package retry_test

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/retry"
	"github.com/obolnetwork/charon/core"
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
			ctxTimeoutFunc := func(ctx context.Context, _ core.Duty) (context.Context, context.CancelFunc) {
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

			retryer := retry.NewForT(t, ctxTimeoutFunc, backoffProvider)
			var attempt int
			_ = retryer.DoAsync(ctx, core.NewAttesterDuty(999), "test", "test", func(ctx context.Context) error {
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
	defer func() {
		require.NoError(t, bmock.Close())
	}()
	require.NoError(t, err)

	deadlineFunc, err := core.NewDutyDeadlineFunc(ctx, bmock)
	require.NoError(t, err)

	retryer := retry.New[core.Duty](deadlineFunc)

	const n = 3
	waiting := make(chan struct{}, n)
	stop := make(chan struct{})
	done := make(chan struct{})

	// Start 3 long-running functions
	for i := 0; i < 3; i++ {
		go func() {
			require.NoError(t,
				retryer.DoAsync(ctx, core.NewProposerDuty(999999), "test", "test", func(ctx context.Context) error {
					waiting <- struct{}{}
					<-stop
					<-ctx.Done()

					return ctx.Err()
				}),
			)
		}()
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

func TestRacyShutdown(t *testing.T) {
	ctx := context.Background()
	bmock, err := beaconmock.New()
	defer func() {
		require.NoError(t, bmock.Close())
	}()
	require.NoError(t, err)

	deadlineFunc, err := core.NewDutyDeadlineFunc(ctx, bmock)
	require.NoError(t, err)

	retryer := retry.New[core.Duty](deadlineFunc)

	const n = 3
	waiting := make(chan struct{}, n)
	stop := make(chan struct{})
	done := make(chan struct{})

	// Start 3 long-running functions
	for i := 0; i < 3; i++ {
		go func() {
			// We're not expecting any errors here, because Shutdown() hasn't been called yet.
			require.NoError(t,
				retryer.DoAsync(ctx, core.NewProposerDuty(999999), "test", "test", func(ctx context.Context) error {
					waiting <- struct{}{}
					<-stop
					<-ctx.Done()

					return ctx.Err()
				}),
			)
		}()
	}

	// Wait for functions to block
	for i := 0; i < n; i++ {
		<-waiting
	}

	// Trigger shutdown
	go func() {
		go retryer.Shutdown(ctx)

		go func() {
			// We *might* expect an error here: since Shutdown() is called in a goroutine, the runtime might decide to
			// schedule its execution *before or after* this one.
			// So, to test the race condition we expect either no error, or a "shutdown in progress" error.
			// Both are fine.
			err := retryer.DoAsync(ctx, core.NewProposerDuty(999999), "test", "test", func(ctx context.Context) error {
				waiting <- struct{}{}
				<-stop
				<-ctx.Done()

				return ctx.Err()
			})
			if err != nil {
				require.ErrorContains(t, err, "shutdown in process")
			}
		}()

		close(done)
	}()

	runtime.Gosched()

	close(stop)
	<-done
}
