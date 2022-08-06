// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package forkjoin_test

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/forkjoin"
)

func TestFastFail(t *testing.T) {
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
			var opts []forkjoin.Option
			if test.failfast {
				opts = append(opts, forkjoin.WithFailFast())
			}

			fork, join := forkjoin.New[int, int](ctx, test.work, opts...)

			var allOutput []int
			for i := 0; i < n; i++ {
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
	fork, join := forkjoin.New[int, int](context.Background(), nil)
	resp, err := join().Flatten()
	require.NoError(t, err)
	require.Empty(t, resp)

	// Calling fork after join panics
	require.Panics(t, func() {
		fork(0)
	})

	// Calling join again panics
	require.Panics(t, func() {
		join()
	})
}
