// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package log

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	zaplogfmt "github.com/jsternberg/zap-logfmt"
	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

// logger is the global logger.
var logger = newConsoleLogger(zapcore.DebugLevel)

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
	level, err := config.ZapLevel()
	if err != nil {
		return err
	}

	if config.Format == "console" {
		logger = newConsoleLogger(level)
		return nil
	}

	encConfig := zap.NewProductionEncoderConfig()
	encoder := zapcore.NewJSONEncoder(encConfig)
	if config.Format == "logfmt" {
		encConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder
		encoder = zaplogfmt.NewEncoder(encConfig)
	} else if config.Format != "json" {
		return errors.New("logger format not console, logfmt or json", z.Str("format", config.Format))
	}

	logger = zap.New(
		zapcore.NewCore(
			encoder,
			os.Stderr,
			zap.NewAtomicLevelAt(level),
		),
		zap.WithCaller(true),
		zap.AddCallerSkip(1),
	)

	return nil
}

// InitLoggerForT initialises a console logger for testing purposes.
func InitLoggerForT(_ *testing.T, ws zapcore.WriteSyncer, opts ...func(*zapcore.EncoderConfig)) {
	logger = buildConsoleLogger(zapcore.DebugLevel, ws, opts...)
}

func newConsoleLogger(level zapcore.Level) *zap.Logger {
	writer, _, _ := zap.Open("stderr")
	return buildConsoleLogger(level, writer)
}

// buildConsoleLogger returns an opinionated console logger.
func buildConsoleLogger(level zapcore.Level, ws zapcore.WriteSyncer, opts ...func(*zapcore.EncoderConfig)) *zap.Logger {
	encConfig := zap.NewDevelopmentEncoderConfig()
	encConfig.ConsoleSeparator = " "
	encConfig.EncodeLevel = level4CharEncoder
	encConfig.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05.000")

	for _, opt := range opts {
		opt(&encConfig)
	}

	encoder := customEncoder{Encoder: zapcore.NewConsoleEncoder(encConfig)}

	return zap.New(
		zapcore.NewCore(
			encoder, ws,
			zap.NewAtomicLevelAt(level),
		),
		zap.WithCaller(true),
		zap.AddCallerSkip(1),
	)
}

// customEncoder wraps an encoder and transforms stacktrace fields to concise entry stack traces and
// prepends a green "topic".
type customEncoder struct {
	zapcore.Encoder
}

func (e customEncoder) EncodeEntry(ent zapcore.Entry, fields []zap.Field) (*buffer.Buffer, error) {
	filtered := make([]zap.Field, 0, len(fields))

	for _, f := range fields {
		const stackKey = "stacktrace"
		if f.Key == stackKey {
			m := zapcore.NewMapObjectEncoder()
			f.AddTo(m)
			stack, ok := m.Fields[stackKey].(string)
			if !ok {
				continue
			}
			ent.Stack = formatZapStack(stack)

			continue
		}

		const topicKey = "topic"
		if f.Key == topicKey {
			m := zapcore.NewMapObjectEncoder()
			f.AddTo(m)
			topic, ok := m.Fields[topicKey].(string)
			if !ok {
				continue
			}

			const green = uint8(32)

			topic = (topic + "          ")[:10] // Align topic spacing.
			topic = fmt.Sprintf("\x1b[%dm%s\x1b[0m", green, topic)

			ent.LoggerName = topic

			continue
		}

		filtered = append(filtered, f)
	}

	// Use only file and line for caller and move to fields.
	if ent.Caller.Defined {
		filtered = append(filtered, zap.String("caller", filepath.Base(ent.Caller.TrimmedPath())))
		ent.Caller.Defined = false
	}

	return e.Encoder.EncodeEntry(ent, filtered)
}

// formatZapStack formats the zap generated stack for concise console printing.
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
func level4CharEncoder(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	replace, ok := level4Map[l]
	trimLevel := func(level string) string {
		if !ok {
			return level
		}

		return strings.Replace(level, l.CapitalString(), replace, 1)
	}
	zapcore.CapitalColorLevelEncoder(l, appendWrapper{enc, trimLevel})
}

// appendWrapper wraps zapcore.PrimitiveArrayEncoder's AppendString function with custom transformation function.
type appendWrapper struct {
	zapcore.PrimitiveArrayEncoder
	appendWrapFunc func(string) string
}

func (w appendWrapper) AppendString(s string) {
	w.PrimitiveArrayEncoder.AppendString(w.appendWrapFunc(s))
}
