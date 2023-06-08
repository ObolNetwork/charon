// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package version_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/version"
)

func TestSemVerCompare(t *testing.T) {
	tests := []struct {
		A   string
		B   string
		Val int
	}{
		{
			A:   "v0.1.0",
			B:   "v0.1.0",
			Val: 0,
		},
		{
			A:   "v0.1.0",
			B:   "v0.1.1",
			Val: -1,
		},
		{
			A:   "v0.1.1",
			B:   "v0.1.0",
			Val: 1,
		},
		{
			A:   "v0.1.1",
			B:   "v0.1",
			Val: 0,
		},
		{
			A:   "v0.2.1",
			B:   "v0.1",
			Val: 1,
		},
		{
			A:   "v0.1",
			B:   "v0.1-dev",
			Val: 0,
		},
		{
			A:   "v0.1-dev",
			B:   "v0.2",
			Val: -1,
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%s-%s", test.A, test.B), func(t *testing.T) {
			a, err := version.Parse(test.A)
			require.NoError(t, err)
			b, err := version.Parse(test.B)
			require.NoError(t, err)
			require.Equal(t, test.Val, version.Compare(a, b))
		})
	}
}

func TestCurrentInSupported(t *testing.T) {
	require.Equal(t, 0, version.Compare(version.Version, version.Supported()[0]))
}

func TestSupportedAreminors(t *testing.T) {
	for _, v := range version.Supported() {
		require.Equal(t, 0, version.Compare(v, v.Minor()))
	}
}

func TestMultiSupported(t *testing.T) {
	require.True(t, len(version.Supported()) > 1)
}
