// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package stacksnipe_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/stacksnipe"
)

type procEntry struct {
	pid      uint64
	procName string
	cmdline  string
}

type snipeResult struct {
	names    []string
	cmdlines []string
}

func Test_StackSnipe(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		baseDir := t.TempDir()

		names := []string{
			"lighthouse",
			"nimbus",
			"node",
		}

		namesExpected := []string{
			"lighthouse",
			"nimbus",
			"lodestar",
		}

		cmdlines := []string{
			"lighthouse_1",
			"nimbus_1",
			"lodestar vc 1",
		}

		extraNames := []string{
			"systemd-resolved",
		}

		extraCmdlines := []string{
			"run_1",
		}

		for idx := 0; idx < len(names); idx++ {
			populateProc(t, baseDir, procEntry{
				pid:      uint64(42 + idx),
				procName: names[idx],
				cmdline:  cmdlines[idx],
			})
		}

		for idx := 0; idx < len(extraNames); idx++ {
			populateProc(t, baseDir, procEntry{
				pid:      uint64(52 + idx),
				procName: extraNames[idx],
				cmdline:  extraCmdlines[idx],
			})
		}

		var (
			ctx, cancel = context.WithCancel(context.Background())
			resultChan  = make(chan snipeResult)
		)

		defer cancel()

		snipe := stacksnipe.NewWithInterval(baseDir, func(names []string, cmdlines []string) {
			resultChan <- snipeResult{
				names:    names,
				cmdlines: cmdlines,
			}

			cancel()
		}, 50*time.Millisecond)

		go snipe.Run(ctx)

		result := <-resultChan

		require.Len(t, result.names, 3)
		require.Len(t, result.cmdlines, 3)

		require.ElementsMatch(t, result.names, namesExpected)
		require.ElementsMatch(t, result.cmdlines, cmdlines)

		for idx := 0; idx < len(extraNames); idx++ {
			require.NotContains(t, result.names, extraNames[idx])
			require.NotContains(t, result.cmdlines, extraCmdlines[idx])
		}
	})
}

func populateProc(t *testing.T, base string, entry procEntry) {
	t.Helper()

	procDir := filepath.Join(base, strconv.FormatUint(entry.pid, 10))
	commFile := filepath.Join(procDir, "comm")
	cmdlineFile := filepath.Join(procDir, "cmdline")

	require.NoError(t, os.Mkdir(procDir, 0o755))
	require.NoError(t, os.WriteFile(commFile, []byte(entry.procName), 0o755))
	require.NoError(t, os.WriteFile(cmdlineFile, []byte(entry.cmdline), 0o755))
}
