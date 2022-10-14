// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package log

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	zaplogfmt "github.com/jsternberg/zap-logfmt"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

const (
	padLength = 40
	keyStack  = "stacktrace"
	keyTopic  = "topic"
)

// logger is the global logger.
var (
	logger = newDefaultLogger()
	initMu sync.Mutex

	padding = strings.Repeat(" ", padLength)
)

// Config defines the logging configuration.
type Config struct {
	Level  string // debug, info, warn or error
	Format string // console or json
}

// ZapLevel returns the zapcore level.
func (c Config) ZapLevel() (zapcore.Level, error) {
	level, err := zapcore.ParseLevel(c.Level)
	if err != nil {
		return 0, errors.Wrap(err, "parse level")
	}

	return level, nil
}

// DefaultConfig returns the default logging config.
func DefaultConfig() Config {
	return Config{
		Level:  zapcore.DebugLevel.String(),
		Format: "console",
	}
}

// InitLogger initialises the global logger based on the provided config.
func InitLogger(config Config) error {
	initMu.Lock()
	defer initMu.Unlock()

	level, err := config.ZapLevel()
	if err != nil {
		return err
	}

	writer, _, err := zap.Open("stderr")
	if err != nil {
		return errors.Wrap(err, "open writer")
	}

	if config.Format == "console" {
		logger = newConsoleLogger(level, writer)
		return nil
	}

	logger, err = newStructuredLogger(config.Format, level, writer)
	if err != nil {
		return err
	}

	return nil
}

// InitConsoleForT initialises a console logger for testing purposes.
func InitConsoleForT(_ *testing.T, ws zapcore.WriteSyncer, opts ...func(*zapcore.EncoderConfig)) {
	initMu.Lock()
	defer initMu.Unlock()
	logger = newConsoleLogger(zapcore.DebugLevel, ws, opts...)
}

// InitJSONForT initialises a json logger for testing purposes.
func InitJSONForT(t *testing.T, ws zapcore.WriteSyncer, opts ...func(*zapcore.EncoderConfig)) {
	t.Helper()
	initMu.Lock()
	defer initMu.Unlock()

	var err error
	logger, err = newStructuredLogger("json", zapcore.DebugLevel, ws, opts...)
	require.NoError(t, err)
}

// InitLogfmtForT initialises a logfmt logger for testing purposes.
func InitLogfmtForT(t *testing.T, ws zapcore.WriteSyncer, opts ...func(*zapcore.EncoderConfig)) {
	t.Helper()
	initMu.Lock()
	defer initMu.Unlock()

	var err error
	logger, err = newStructuredLogger("logfmt", zapcore.DebugLevel, ws, opts...)
	require.NoError(t, err)
}

// newStructuredLogger returns an opinionated logfmt or json logger.
func newStructuredLogger(format string, level zapcore.Level, ws zapcore.WriteSyncer, opts ...func(*zapcore.EncoderConfig)) (*zap.Logger, error) {
	encConfig := zap.NewProductionEncoderConfig()
	encConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder

	for _, opt := range opts {
		opt(&encConfig)
	}

	var encoder zapcore.Encoder
	switch format {
	case "logfmt":
		encoder = zaplogfmt.NewEncoder(encConfig)
	case "json":
		encoder = zapcore.NewJSONEncoder(encConfig)
	default:
		return nil, errors.New("invalid logger format; not console, logfmt or json", z.Str("format", format))
	}

	structured := structuredEncoder{
		Encoder:        encoder,
		consoleEncoder: newConsoleEncoder(false, true, false),
	}

	return zap.New(
		zapcore.NewCore(structured, ws, zap.NewAtomicLevelAt(level)),
		zap.WithCaller(true),
		zap.AddCallerSkip(1),
	), nil
}

// newDefaultLogger returns an opinionated console logger writing to stderr.
func newDefaultLogger() *zap.Logger {
	writer, _, _ := zap.Open("stderr")
	return newConsoleLogger(zapcore.DebugLevel, writer)
}

// newConsoleEncoder returns a zap encoder that generates console logs.
func newConsoleEncoder(timestamp, color, stacktrace bool, opts ...func(*zapcore.EncoderConfig)) zapcore.Encoder {
	encConfig := zap.NewDevelopmentEncoderConfig()
	encConfig.ConsoleSeparator = " "
	encConfig.EncodeLevel = newLevel4CharEncoder(color)
	if !timestamp {
		encConfig.EncodeTime = func(time.Time, zapcore.PrimitiveArrayEncoder) {}
	} else {
		encConfig.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05.000")
	}
	for _, opt := range opts {
		opt(&encConfig)
	}

	return consoleEncoder{
		Encoder:    zapcore.NewConsoleEncoder(encConfig),
		color:      color,
		stacktrace: stacktrace,
	}
}

// newConsoleLogger returns an opinionated console logger.
func newConsoleLogger(level zapcore.Level, ws zapcore.WriteSyncer, opts ...func(*zapcore.EncoderConfig)) *zap.Logger {
	return zap.New(
		zapcore.NewCore(
			newConsoleEncoder(true, true, true, opts...),
			ws,
			zap.NewAtomicLevelAt(level),
		),
	)
}

// structuredEncoder wraps a structured encoder and transforms fields:
// - Adds a "pretty" field which is the console formatted version of the log.
// - Formats concise "stacktrace" fields.
type structuredEncoder struct {
	zapcore.Encoder
	consoleEncoder zapcore.Encoder
}

func (e structuredEncoder) EncodeEntry(ent zapcore.Entry, fields []zap.Field) (*buffer.Buffer, error) {
	pretty, err := e.consoleEncoder.EncodeEntry(ent, append([]zap.Field(nil), fields...))
	if err != nil {
		return nil, err
	}
	fields = append(fields, zap.String("pretty", pretty.String()))

	for i, f := range fields {
		if f.Key == keyStack {
			fields[i].String = formatZapStack(f.String)
			ent.Stack = ""

			break
		}
	}

	return e.Encoder.EncodeEntry(ent, fields)
}

// consoleEncoder wraps an encoder and transforms fields:
//   - "stacktrace" fields to concise entry stack traces if enabled, otherwise stack traces are removed.
//   - prepends "topic" fields as "logger name", coloring it green if color enabled.
//   - pads the "message" so fields are aligned.
type consoleEncoder struct {
	zapcore.Encoder
	color      bool
	stacktrace bool
}

func (e consoleEncoder) EncodeEntry(ent zapcore.Entry, fields []zap.Field) (*buffer.Buffer, error) {
	filtered := make([]zap.Field, 0, len(fields))

	for _, f := range fields {
		if f.Key == keyStack {
			if e.stacktrace {
				ent.Stack = formatZapStack(f.String)
			}

			continue
		}

		if f.Key == keyTopic {
			const green = uint8(32)

			topic := (f.String + "          ")[:10] // Align topic spacing.
			if e.color {
				topic = fmt.Sprintf("\x1b[%dm%s\x1b[0m", green, topic)
			}
			ent.LoggerName = topic

			continue
		}

		filtered = append(filtered, f)
	}

	ent.Caller.Defined = false // Do not log caller in console

	if len(ent.Message) < padLength {
		ent.Message = (ent.Message + padding)[:padLength] // Align message spacing.
	}

	return e.Encoder.EncodeEntry(ent, filtered)
}

// formatZapStack formats the zap generated stack for concise printing.
func formatZapStack(zapStack string) string {
	var (
		resp     []string
		prevFunc string
	)

	for _, line := range strings.Split(zapStack, "\n") {
		if strings.HasPrefix(line, "\t") {
			const sep = "charon/"
			i := strings.LastIndex(line, sep)
			if i < 0 {
				// Skip non-charon lines
				continue
			}

			resp = append(resp, "\t"+line[i+len(sep):]+" "+prevFunc)
			prevFunc = ""

			continue
		}

		if i := strings.LastIndex(line, "."); i > 0 {
			prevFunc = line[i:]
		}
	}

	return strings.Join(resp, "\n")
}

// level4Map defines 4 character mappings of log levels.
var level4Map = map[zapcore.Level]string{
	zapcore.DebugLevel: "DEBG",
	zapcore.ErrorLevel: "ERRO",
	// Levels below not actually used.
	zapcore.DPanicLevel: "PNIC",
	zapcore.PanicLevel:  "PNIC",
	zapcore.FatalLevel:  "FATL",
}

// level4CharEncoder adapts zapcore CapitalColorLevelEncoder but trims level strings to 4 characters.
func newLevel4CharEncoder(color bool) zapcore.LevelEncoder {
	return func(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
		replace, ok := level4Map[l]
		trimLevel := func(level string) string {
			if !ok {
				return level
			}

			return strings.Replace(level, l.CapitalString(), replace, 1)
		}
		wrappedEnc := appendWrapper{enc, trimLevel}

		if !color {
			zapcore.CapitalLevelEncoder(l, wrappedEnc)
			return
		}
		zapcore.CapitalColorLevelEncoder(l, wrappedEnc)
	}
}

// appendWrapper wraps zapcore.PrimitiveArrayEncoder's AppendString function with custom transformation function.
type appendWrapper struct {
	zapcore.PrimitiveArrayEncoder
	appendWrapFunc func(string) string
}

func (w appendWrapper) AppendString(s string) {
	w.PrimitiveArrayEncoder.AppendString(w.appendWrapFunc(s))
}
