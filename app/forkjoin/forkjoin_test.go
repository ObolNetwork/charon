// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package forkjoin_test

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/forkjoin"
)

func TestForkJoin(t *testing.T) {
	ctx := context.Background()

	const n = 100

	testErr := errors.New("test error")

	tests := []struct {
		name        string
		work        forkjoin.Work[int, int]
		failfast    bool
		expectedErr error
		allOutput   bool
	}{
		{
			name:        "happy",
			expectedErr: nil,
			work:        func(_ context.Context, i int) (int, error) { return i, nil },
			allOutput:   true,
		},
		{
			name:        "first error fast fail",
			expectedErr: testErr,
			failfast:    true,
			work: func(ctx context.Context, i int) (int, error) {
				if i == 0 {
					return 0, testErr
				}
				if i > n/2 {
					require.Fail(t, "not failed fast")
				}
				<-ctx.Done() // This will hang if not failing fast

				return 0, ctx.Err()
			},
		},
		{
			name:        "all error no fast fail",
			allOutput:   true,
			expectedErr: testErr,
			work: func(_ context.Context, i int) (int, error) {
				return i, testErr
			},
		},
		{
			name:        "all context cancel",
			expectedErr: context.Canceled,
			failfast:    true,
			work: func(_ context.Context, i int) (int, error) {
				if i < n/2 {
					return 0, context.Canceled
				}

				return 0, nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer goleak.VerifyNone(t)

			var opts []forkjoin.Option
			if !test.failfast {
				opts = append(opts, forkjoin.WithoutFailFast())
			}

			fork, join, cancel := forkjoin.New[int, int](ctx, test.work, opts...)
			defer cancel()

			var allOutput []int

			for i := range n {
				fork(i)
				allOutput = append(allOutput, i)
			}

			resp, err := join().Flatten()
			require.Len(t, resp, n)

			if test.expectedErr != nil {
				require.Equal(t, test.expectedErr, err)
			} else {
				require.NoError(t, err)
			}

			if test.allOutput {
				sort.Ints(resp)
				require.Equal(t, allOutput, resp)
			}
		})
	}
}

func TestPanic(t *testing.T) {
	defer goleak.VerifyNone(t)

	fork, join, cancel := forkjoin.New[int, int](context.Background(), nil, forkjoin.WithWaitOnCancel())
	join()
	cancel()

	// Calling fork after join panics
	require.Panics(t, func() {
		fork(0)
	})

	// Calling join again panics
	require.Panics(t, func() {
		join()
	})
}

func TestLeak(t *testing.T) {
	defer goleak.VerifyNone(t)

	fork, join, cancel := forkjoin.New[int, int](
		context.Background(),
		func(ctx context.Context, i int) (int, error) { return i, nil },
		forkjoin.WithWaitOnCancel(),
	)
	fork(1)
	fork(2)

	results := join()
	<-results // Read 1 or 2
	cancel()  // Fails if not called.
}
