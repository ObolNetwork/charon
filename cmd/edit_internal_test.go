// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/obolnetwork/charon/app/log"
)

func TestLogProposerConfigOutput(t *testing.T) {
	t.Run("written", func(t *testing.T) {
		var logs zaptest.Buffer

		log.InitLogfmtForT(t, &logs)

		outputDir := t.TempDir()
		path := filepath.Join(outputDir, "vc-config", "proposer-config.json")
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte("{}"), 0o644))

		logProposerConfigOutput(t.Context(), outputDir)

		require.Contains(t, logs.String(), path)
		require.Contains(t, logs.String(), "replaces your current vc-config/proposer-config.json")
	})

	t.Run("removed operator gets none", func(t *testing.T) {
		var logs zaptest.Buffer

		log.InitLogfmtForT(t, &logs)

		logProposerConfigOutput(t.Context(), t.TempDir())

		require.NotContains(t, logs.String(), "re-signed")
	})
}
