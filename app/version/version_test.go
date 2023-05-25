// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package version_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/version"
)

func TestMinor(t *testing.T) {
	minor, err := version.Minor("v0.1.2")
	require.NoError(t, err)
	require.Equal(t, "v0.1", minor)

	minor, err = version.Minor("1.2.3")
	require.NoError(t, err)
	require.Equal(t, "1.2", minor)

	minor, err = version.Minor("version 1000.2000.3000")
	require.NoError(t, err)
	require.Equal(t, "version 1000.2000", minor)

	minor, err = version.Minor("v0.1")
	require.NoError(t, err)
	require.Equal(t, "v0.1", minor)

	minor, err = version.Minor("v0.1.2.3")
	require.NoError(t, err)
	require.Equal(t, "v0.1", minor)

	_, err = version.Minor("0")
	require.ErrorContains(t, err, "invalid version string")

	_, err = version.Minor("foo")
	require.ErrorContains(t, err, "invalid version string")

	minor, err = version.Minor("v0.1-rc1")
	require.NoError(t, err)
	require.Equal(t, "v0.1", minor)
}

func TestCurrentInSupported(t *testing.T) {
	require.Contains(t, version.Version, version.Supported()[0])
}

func TestSupportedAreMinors(t *testing.T) {
	for _, v := range version.Supported() {
		minor, err := version.Minor(v)
		require.NoError(t, err)
		require.Equal(t, v, minor)
	}
}

func TestMultiSupported(t *testing.T) {
	require.True(t, len(version.Supported()) > 1)
}
