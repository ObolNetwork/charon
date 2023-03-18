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
}
