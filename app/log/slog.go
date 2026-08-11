// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

//nolint:revive,nolintlint // somehow the nolintlint linter catches revive as unnecessary, while it is
package log

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"

	"go.uber.org/zap/zapcore"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

// SlogHandler returns a slog.Handler that writes records to the global charon logger.
// It routes go-libp2p's slog based (gologshim) logs into charon logging, since those
// bypass the go-log primary zap core.
//
// Per-subsystem levels are controlled by the GOLOG_LOG_LEVEL environment variable
// (comma-separated [subsystem=]level pairs, e.g. "net/identify=debug") with a fallback
// level of error, matching gologshim defaults. The subsystem is detected from the
// "logger" attribute that gologshim attaches to each of its loggers.
func SlogHandler() slog.Handler {
	levels := slogLevels()

	return &slogHandler{
		levels: levels,
		level:  levels.fallback,
	}
}

// slogHandler implements slog.Handler by writing records to the global logger core.
type slogHandler struct {
	fields []zapcore.Field
	groups []string
	levels *slogLevelConfig
	level  slog.Level
}

func (h *slogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *slogHandler) Handle(_ context.Context, rec slog.Record) error {
	// Never let a logging panic crash the process.
	defer func() {
		if r := recover(); r != nil {
			defer func() {
				if r2 := recover(); r2 != nil {
					fmt.Fprintf(os.Stderr, "slog handler panic (logging also failed): %v\n", r)
				}
			}()

			Error(context.Background(), "Libp2p slog handler panic, log line dropped",
				errors.New("slog handler panic", z.Str("panic", fmt.Sprint(r))))
		}
	}()

	entry := zapcore.Entry{
		Level:   toZapLevel(rec.Level),
		Time:    rec.Time,
		Message: rec.Message,
		Caller:  toZapCaller(rec.PC),
	}

	fields := make([]zapcore.Field, 0, len(h.fields)+rec.NumAttrs()+1)
	fields = append(fields, zapcore.Field{Key: "topic", Type: zapcore.StringType, String: "libp2p"})
	fields = append(fields, h.fields...)

	rec.Attrs(func(a slog.Attr) bool {
		fields = append(fields, h.toZapField(a))
		return true
	})

	// Read the global logger core directly (unlocked), matching getLogger's hot
	// path, rather than LoggerCore which locks on every record.
	ce := logger.Core().Check(entry, nil)
	if ce == nil {
		return nil
	}

	ce.Write(fields...)

	return nil
}

func (h *slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	resp := h.clone()

	for _, a := range attrs {
		if a.Key == "logger" && a.Value.Kind() == slog.KindString {
			// Gologshim identifies each subsystem via the "logger" attribute,
			// which determines its GOLOG_LOG_LEVEL based level.
			resp.level = h.levels.levelFor(a.Value.String())
		}

		resp.fields = append(resp.fields, h.toZapField(a))
	}

	return resp
}

func (h *slogHandler) WithGroup(name string) slog.Handler {
	resp := h.clone()
	resp.groups = append(resp.groups, name)

	return resp
}

// clone returns a copy of the handler with fields and groups slices safe to append to.
func (h *slogHandler) clone() *slogHandler {
	return &slogHandler{
		fields: append([]zapcore.Field(nil), h.fields...),
		groups: append([]string(nil), h.groups...),
		levels: h.levels,
		level:  h.level,
	}
}

// toZapField converts a slog attribute to a zap field, prefixing open group names.
// All values are stringified to avoid zapcore.ReflectType, which panics in the
// logfmt encoder on named types (e.g. protocol.ID).
func (h *slogHandler) toZapField(a slog.Attr) zapcore.Field {
	key := a.Key
	if len(h.groups) > 0 {
		key = strings.Join(h.groups, ".") + "." + key
	}

	return zapcore.Field{Key: key, Type: zapcore.StringType, String: fmt.Sprint(a.Value.Resolve().Any())}
}

// toZapLevel maps a slog level to the closest zap level.
func toZapLevel(level slog.Level) zapcore.Level {
	switch {
	case level >= slog.LevelError:
		return zapcore.ErrorLevel
	case level >= slog.LevelWarn:
		return zapcore.WarnLevel
	case level >= slog.LevelInfo:
		return zapcore.InfoLevel
	default:
		return zapcore.DebugLevel
	}
}

// toZapCaller resolves a slog record program counter to a zap entry caller.
func toZapCaller(pc uintptr) zapcore.EntryCaller {
	if pc == 0 {
		return zapcore.EntryCaller{}
	}

	frame, _ := runtime.CallersFrames([]uintptr{pc}).Next()
	if frame.PC == 0 {
		return zapcore.EntryCaller{}
	}

	return zapcore.EntryCaller{
		Defined:  true,
		PC:       frame.PC,
		File:     frame.File,
		Line:     frame.Line,
		Function: frame.Function,
	}
}

// slogLevelConfig holds per-subsystem slog levels parsed from GOLOG_LOG_LEVEL.
type slogLevelConfig struct {
	fallback slog.Level
	systems  map[string]slog.Level
}

// levelFor returns the level for the given subsystem, or the fallback level.
func (c *slogLevelConfig) levelFor(system string) slog.Level {
	level, ok := c.systems[system]
	if !ok {
		return c.fallback
	}

	return level
}

// slogLevels returns the levels parsed from the GOLOG_LOG_LEVEL environment
// variable, mirroring gologshim (and go-log) semantics.
var slogLevels = sync.OnceValue(func() *slogLevelConfig {
	return parseSlogLevels(os.Getenv("GOLOG_LOG_LEVEL"))
})

// parseSlogLevels parses a comma-separated list of [subsystem=]level pairs,
// invalid entries are ignored and the fallback level defaults to error.
func parseSlogLevels(env string) *slogLevelConfig {
	resp := &slogLevelConfig{
		fallback: slog.LevelError,
		systems:  make(map[string]slog.Level),
	}

	for kvs := range strings.SplitSeq(env, ",") {
		if kvs == "" {
			continue
		}

		kv := strings.SplitN(kvs, "=", 2)

		var level slog.Level

		err := level.UnmarshalText([]byte(kv[len(kv)-1]))
		if err != nil {
			continue // Ignore invalid levels.
		}

		if len(kv) == 1 {
			resp.fallback = level
		} else {
			resp.systems[kv[0]] = level
		}
	}

	return resp
}
