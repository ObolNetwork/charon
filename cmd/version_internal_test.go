// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/core/consensus/protocols"
)

func TestRunVersionCmd(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		var buf bytes.Buffer

		runVersionCmd(&buf, versionConfig{Verbose: false})

		str := buf.String()
		require.Contains(t, str, "git_commit_hash")
		require.Contains(t, str, "git_commit_time")
		require.NotContains(t, str, "Package:")
		require.NotContains(t, str, "/n")

		parts := strings.Split(str, " ")
		require.Len(t, parts, 2)

		semver, err := version.Parse(parts[0])
		require.NoError(t, err)
		require.Equal(t, version.Version, semver)
	})

	t.Run("verbose", func(t *testing.T) {
		var buf bytes.Buffer

		runVersionCmd(&buf, versionConfig{Verbose: true})

		str := buf.String()
		require.Contains(t, str, "git_commit_hash")
		require.Contains(t, str, "git_commit_time")
		require.Contains(t, str, "Package:")
		require.Contains(t, str, "Dependencies:")
		require.Contains(t, str, "Consensus protocols:")
		require.Contains(t, str, protocols.Protocols()[0])
	})
}
