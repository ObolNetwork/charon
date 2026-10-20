// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAlphaEditAlias(t *testing.T) {
	root := New()

	for _, name := range []string{"add-validators", "add-operators", "remove-operators", "replace-operator", "recreate-private-keys"} {
		stable, _, err := root.Find([]string{"edit", name})
		require.NoError(t, err)
		require.Equal(t, name, stable.Name())
		require.Empty(t, stable.Deprecated)

		alias, _, err := root.Find([]string{"alpha", "edit", name})
		require.NoError(t, err)
		require.Equal(t, name, alias.Name())
		require.Equal(t, "use 'charon edit "+name+"' instead", alias.Deprecated)
		require.True(t, alias.Parent().Hidden)
	}
}
