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
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

var logger = newConsoleLogger()

func newConsoleLogger() *zap.Logger {
	encConfig := zap.NewDevelopmentEncoderConfig()
	encConfig.ConsoleSeparator = " "
	encConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	encConfig.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05.000")

	writer, _, _ := zap.Open("stderr")

	return buildConsoleLogger(encConfig, writer)
}

// InitJSONLogger initialises a JSON logger for production usage.
func InitJSONLogger() error {
	var err error
	logger, err = zap.NewProduction()

	return err
}

// InitLoggerForT initialises a console logger for testing purposes.
func InitLoggerForT(_ *testing.T, encConfig zapcore.EncoderConfig, ws zapcore.WriteSyncer) {
	logger = buildConsoleLogger(encConfig, ws)
}

// buildConsoleLogger returns an opinionated console logger.
func buildConsoleLogger(encConfig zapcore.EncoderConfig, ws zapcore.WriteSyncer) *zap.Logger {
	encoder := customEncoder{Encoder: zapcore.NewConsoleEncoder(encConfig)}

	return zap.New(
		zapcore.NewCore(
			encoder, ws,
			zap.NewAtomicLevelAt(zapcore.DebugLevel),
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
