// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package stacksnipe_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

		for idx := range len(names) {
			populateProc(t, baseDir, procEntry{
				pid:      uint64(42 + idx),
				procName: names[idx],
				cmdline:  cmdlines[idx],
			})
		}

		for idx := range len(extraNames) {
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

		for idx := range len(extraNames) {
			require.NotContains(t, result.names, extraNames[idx])
			require.NotContains(t, result.cmdlines, extraCmdlines[idx])
		}
	})

	t.Run("redacts secret flag values", func(t *testing.T) {
		baseDir := t.TempDir()

		// A real /proc cmdline is NUL separated, one argument per element.
		populateProc(t, baseDir, procEntry{
			pid:      42,
			procName: "lighthouse",
			cmdline: strings.Join([]string{
				"/usr/bin/lighthouse", "vc",
				"--datadir", "/var/lib/lighthouse",
				"--validators-keystore-password-file", "/run/secrets/vc-password.txt",
				"--keystore-password", "SuperSecretPw123!",
				"--suggested-fee-recipient", "0xdeadbeef",
				"--debug-level", "info",
			}, "\x00"),
		})

		populateProc(t, baseDir, procEntry{
			pid:      43,
			procName: "teku",
			cmdline: strings.Join([]string{
				"/usr/bin/teku", "validator-client",
				"--data-path", "/var/lib/teku",
				"--keymanager-auth-token=eyJhbGciOiJSUzI1NiJ9.secret-jwt",
				"--validators-external-signer-url", "https://signer.internal:9000",
			}, "\x00"),
		})

		var (
			ctx, cancel = context.WithCancel(context.Background())
			resultChan  = make(chan snipeResult)
		)

		defer cancel()

		snipe := stacksnipe.NewWithInterval(baseDir, func(names []string, cmdlines []string) {
			resultChan <- snipeResult{names: names, cmdlines: cmdlines}

			cancel()
		}, 50*time.Millisecond)

		go snipe.Run(ctx)

		result := <-resultChan
		require.Len(t, result.cmdlines, 2)

		exported := strings.Join(result.cmdlines, "\n")

		// No secret material survives export, in either the "--flag value" or the "--flag=value" form.
		require.NotContains(t, exported, "SuperSecretPw123!")
		require.NotContains(t, exported, "/run/secrets/vc-password.txt")
		require.NotContains(t, exported, "eyJhbGciOiJSUzI1NiJ9.secret-jwt")

		// The flag names themselves are kept, so the telemetry stays useful.
		require.Contains(t, exported, "--validators-keystore-password-file <redacted>")
		require.Contains(t, exported, "--keystore-password <redacted>")
		require.Contains(t, exported, "--keymanager-auth-token=<redacted>")

		// Non-sensitive flags and their values are untouched.
		require.Contains(t, exported, "--datadir /var/lib/lighthouse")
		require.Contains(t, exported, "--suggested-fee-recipient 0xdeadbeef")
		require.Contains(t, exported, "--debug-level info")
		require.Contains(t, exported, "--data-path /var/lib/teku")
		require.Contains(t, exported, "--validators-external-signer-url https://signer.internal:9000")
	})

	// Redaction must not silently no-op if the whole command line ever arrives as a single
	// argument rather than the NUL separated form a real /proc exposes.
	t.Run("redacts secret flag values in an unsplit command line", func(t *testing.T) {
		baseDir := t.TempDir()

		populateProc(t, baseDir, procEntry{
			pid:      42,
			procName: "lighthouse",
			cmdline:  "/usr/bin/lighthouse vc --keystore-password SuperSecretPw123! --debug-level info",
		})

		var (
			ctx, cancel = context.WithCancel(context.Background())
			resultChan  = make(chan snipeResult)
		)

		defer cancel()

		snipe := stacksnipe.NewWithInterval(baseDir, func(names []string, cmdlines []string) {
			resultChan <- snipeResult{names: names, cmdlines: cmdlines}

			cancel()
		}, 50*time.Millisecond)

		go snipe.Run(ctx)

		result := <-resultChan
		require.Len(t, result.cmdlines, 1)

		require.NotContains(t, result.cmdlines[0], "SuperSecretPw123!")
		require.Contains(t, result.cmdlines[0], "--keystore-password <redacted>")
		require.Contains(t, result.cmdlines[0], "--debug-level info")
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
