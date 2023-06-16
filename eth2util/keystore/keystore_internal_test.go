// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package keystore

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_orderByKeystoreNum(t *testing.T) {
	tests := []struct {
		name     string
		files    []string
		want     []string
		wantIdxs []int
		errCheck require.ErrorAssertionFunc
	}{
		{
			"keystore secure files",
			[]string{
				"/keystore-10.json",
				"/keystore-1.json",
				"/keystore-3.json",
				"/keystore-2.json",
			},
			[]string{
				"/keystore-1.json",
				"/keystore-2.json",
				"/keystore-3.json",
				"/keystore-10.json",
			},
			[]int{1, 2, 3, 10},
			require.NoError,
		},
		{
			"keystore insecure files",
			[]string{
				"/keystore-insecure-10.json",
				"/keystore-insecure-1.json",
				"/keystore-insecure-3.json",
				"/keystore-insecure-2.json",
			},
			[]string{
				"/keystore-insecure-1.json",
				"/keystore-insecure-2.json",
				"/keystore-insecure-3.json",
				"/keystore-insecure-10.json",
			},
			[]int{1, 2, 3, 10},
			require.NoError,
		},
		{
			"filenames that do not pass regex error early",
			[]string{
				"/keystore-insecure-fail.json",
				"/keystore-insecure-failtoo.json",
			},
			nil,
			nil,
			require.Error,
		},
		{
			"single file path yields the exact same thing",
			[]string{
				"/keystore-1.json",
			},
			[]string{
				"/keystore-1.json",
			},
			[]int{1},
			require.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, indices, err := orderByKeystoreNum(tt.files)

			tt.errCheck(t, err)
			require.Equal(t, tt.want, got)
			require.Equal(t, tt.wantIdxs, indices)
		})
	}
}
