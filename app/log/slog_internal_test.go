// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package log

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

func TestParseSlogLevels(t *testing.T) {
	tests := []struct {
		name     string
		env      string
		fallback slog.Level
		systems  map[string]slog.Level
	}{
		{
			name:     "empty defaults to error",
			env:      "",
			fallback: slog.LevelError,
			systems:  map[string]slog.Level{},
		},
		{
			name:     "per system levels",
			env:      "observedaddrs=debug,net/identify=debug",
			fallback: slog.LevelError,
			systems: map[string]slog.Level{
				"observedaddrs": slog.LevelDebug,
				"net/identify":  slog.LevelDebug,
			},
		},
		{
			name:     "fallback and system",
			env:      "warn,autonat=info",
			fallback: slog.LevelWarn,
			systems:  map[string]slog.Level{"autonat": slog.LevelInfo},
		},
		{
			name:     "invalid entries ignored",
			env:      "bogus=notalevel,autonat=debug",
			fallback: slog.LevelError,
			systems:  map[string]slog.Level{"autonat": slog.LevelDebug},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := parseSlogLevels(test.env)
			require.Equal(t, test.fallback, c.fallback)
			require.Equal(t, test.systems, c.systems)
		})
	}
}

func TestSlogHandler(t *testing.T) {
	var buf bytes.Buffer

	InitConsoleForT(t, zapcore.AddSync(&buf))

	levels := parseSlogLevels("net/identify=debug")
	h := slog.Handler(&slogHandler{levels: levels, level: levels.fallback})

	// Subsystem with debug enabled writes debug records to the charon logger.
	identify := slog.New(h.WithAttrs([]slog.Attr{slog.String("logger", "net/identify")}))
	identify.Debug("updating snapshot", "seq", 1)

	require.Contains(t, buf.String(), "updating snapshot")
	require.Contains(t, buf.String(), "net/identify")
	require.Contains(t, buf.String(), "libp2p")

	// Subsystem at fallback level drops debug and info records.
	buf.Reset()

	other := slog.New(h.WithAttrs([]slog.Attr{slog.String("logger", "swarm")}))
	other.Debug("dropped")
	other.Info("also dropped")
	require.Empty(t, buf.String())

	// But writes error records.
	other.Error("failed to listen", "err", "address in use")
	require.Contains(t, buf.String(), "failed to listen")
}

// namedString is a named string type like protocol.ID that is not plain string.
type namedString string

func TestSlogHandlerNamedTypes(t *testing.T) {
	var buf bytes.Buffer

	InitLogfmtForT(t, zapcore.AddSync(&buf))

	levels := parseSlogLevels("identify=debug")
	h := slog.Handler(&slogHandler{levels: levels, level: levels.fallback})
	identify := slog.New(h.WithAttrs([]slog.Attr{slog.String("logger", "identify")}))

	// Logging a slice of named-string types (like []protocol.ID) previously
	// panicked because logfmt's AppendReflected asserts interface{} to string.
	protocols := []namedString{"/proto/1.0", "/proto/2.0"}

	require.NotPanics(t, func() {
		identify.Debug("sending identify", "protocols", protocols)
	})

	require.Contains(t, buf.String(), "sending identify")
	require.Contains(t, buf.String(), "/proto/1.0")

	// Float, int, and bool values must also survive logfmt encoding.
	buf.Reset()
	require.NotPanics(t, func() {
		identify.Debug("peer stats",
			"score", 3.14,
			"conns", 42,
			"relay", true,
		)
	})

	require.Contains(t, buf.String(), "3.14")
	require.Contains(t, buf.String(), "42")
	require.Contains(t, buf.String(), "true")
}
