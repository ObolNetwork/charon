// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package log

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	zaplogfmt "github.com/jsternberg/zap-logfmt"
	"github.com/moby/term"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log/loki"
	"github.com/obolnetwork/charon/app/z"
)

const (
	defaultCallerSkip = 1
	padLength         = 40
	keyStack          = "stacktrace"
	keyTopic          = "topic"
)

const (
	colorDisable = "disable"
	colorForce   = "force"
	colorAuto    = "auto"
)

// zapLogger abstracts a zap logger.
type zapLogger interface {
	Debug(string, ...zap.Field)
	Info(string, ...zap.Field)
	Warn(string, ...zap.Field)
	Error(string, ...zap.Field)
	Core() zapcore.Core
}

var (
	initMu sync.RWMutex
	// logger is the global logger.
	logger zapLogger = newDefaultLogger()
	// stopFuncs are the global logger stop functions.
	stopFuncs []func(context.Context)
	// lokiLabels are the global loki logger labels.
	lokiLabels map[string]string

	padding = strings.Repeat(" ", padLength)
)

// getLokiLabels returns the global loki logger labels and whether they are populated.
func getLokiLabels() (map[string]string, bool) {
	initMu.RLock()
	defer initMu.RUnlock()

	return lokiLabels, lokiLabels != nil
}

// SetLokiLabels sets the global logger loki labels.
func SetLokiLabels(l map[string]string) {
	initMu.Lock()
	defer initMu.Unlock()

	if l == nil {
		lokiLabels = make(map[string]string)
		return
	}

	lokiLabels = l
}

// LoggerCore returns the global logger's zap core.
func LoggerCore() zapcore.Core {
	initMu.Lock()
	defer initMu.Unlock()

	return logger.Core()
}

// Config defines the logging configuration.
type Config struct {
	Level         string   // debug, info, warn or error
	Format        string   // console or json or logfmt
	Color         string   // disable, force or auto
	LokiAddresses []string // URLs for loki logging spout
	LokiService   string   // Value of the service label pushed with loki logs.
}

// ZapLevel returns the zapcore level.
func (c Config) ZapLevel() (zapcore.Level, error) {
	level, err := zapcore.ParseLevel(c.Level)
	if err != nil {
		return 0, errors.Wrap(err, "parse level")
	}

	return level, nil
}

// InferColor returns true if color logs should be used.
func (c Config) InferColor() (bool, error) {
	switch strings.ToLower(strings.TrimSpace(c.Color)) {
	case colorDisable:
		return false, nil
	case colorForce:
		return true, nil
	case colorAuto, "":
		return term.IsTerminal(os.Stderr.Fd()), nil
	}

	return false, errors.New("invalid --log-color value", z.Str("value", c.Color))
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
	Stop(context.Background()) // Stop previously started loggers.

	initMu.Lock()
	defer initMu.Unlock()

	level, err := config.ZapLevel()
	if err != nil {
		return err
	}

	color, err := config.InferColor()
	if err != nil {
		return err
	}

	writer, _, err := zap.Open("stderr")
	if err != nil {
		return errors.Wrap(err, "open writer")
	}

	callerSkip := defaultCallerSkip
	if len(config.LokiAddresses) > 0 {
		callerSkip++
	}

	if config.Format == "console" {
		logger = newConsoleLogger(level, color, writer)
	} else {
		logger, err = newStructuredLogger(config.Format, level, color, writer, callerSkip)
		if err != nil {
			return err
		}
	}

	if len(config.LokiAddresses) > 0 {
		// Wire loki clients internal logger
		ctx := WithTopic(context.Background(), "loki")
		filter := Filter()
		logFunc := func(msg string, err error) {
			Warn(ctx, msg, err, filter)
		}

		// Create a multi logger
		loggers := multiLogger{logger}
		for _, address := range config.LokiAddresses {
			lokiCl := loki.New(address, config.LokiService, logFunc, getLokiLabels)
			lokiLogger, err := newStructuredLogger("logfmt",
				zapcore.DebugLevel, color, lokiWriter{cl: lokiCl}, callerSkip)
			if err != nil {
				return err
			}

			stopFuncs = append(stopFuncs, lokiCl.Stop)
			loggers = append(loggers, lokiLogger)
			go lokiCl.Run()
		}

		logger = loggers
	}

	return nil
}

// InitConsoleForT initialises a console logger for testing purposes.
func InitConsoleForT(_ *testing.T, ws zapcore.WriteSyncer, opts ...func(*zapcore.EncoderConfig)) {
	initMu.Lock()
	defer initMu.Unlock()
	logger = newConsoleLogger(zapcore.DebugLevel, true, ws, opts...)
}

// InitJSONForT initialises a json logger for testing purposes.
func InitJSONForT(t *testing.T, ws zapcore.WriteSyncer, opts ...func(*zapcore.EncoderConfig)) {
	t.Helper()
	initMu.Lock()
	defer initMu.Unlock()

	var err error
	logger, err = newStructuredLogger("json", zapcore.DebugLevel, true, ws, defaultCallerSkip, opts...)
	require.NoError(t, err)
}

// InitLogfmtForT initialises a logfmt logger for testing purposes.
func InitLogfmtForT(t *testing.T, ws zapcore.WriteSyncer, opts ...func(*zapcore.EncoderConfig)) {
	t.Helper()
	initMu.Lock()
	defer initMu.Unlock()

	var err error
	logger, err = newStructuredLogger("logfmt", zapcore.DebugLevel, false, ws, defaultCallerSkip, opts...)
	require.NoError(t, err)
}

// Stop stops all log processors.
func Stop(ctx context.Context) {
	initMu.Lock()
	defer initMu.Unlock()

	for _, stopFunc := range stopFuncs {
		stopFunc(ctx)
	}

	stopFuncs = nil
}

// newStructuredLogger returns an opinionated logfmt or json logger.
func newStructuredLogger(format string, level zapcore.Level, color bool, ws zapcore.WriteSyncer, callerSkip int, opts ...func(*zapcore.EncoderConfig)) (*zap.Logger, error) {
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
		consoleEncoder: newConsoleEncoder(false, color, false),
	}

	return zap.New(
		zapcore.NewCore(structured, ws, zap.NewAtomicLevelAt(level)),
		zap.WithCaller(true),
		zap.AddCallerSkip(callerSkip),
	), nil
}

// newDefaultLogger returns an opinionated console logger writing to stderr.
func newDefaultLogger() *zap.Logger {
	writer, _, _ := zap.Open("stderr")
	return newConsoleLogger(zapcore.DebugLevel, true, writer)
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
func newConsoleLogger(level zapcore.Level, color bool, ws zapcore.WriteSyncer, opts ...func(*zapcore.EncoderConfig)) *zap.Logger {
	return zap.New(
		zapcore.NewCore(
			newConsoleEncoder(true, color, true, opts...),
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
			ent.LoggerName = f.String

			continue
		}

		filtered = append(filtered, f)
	}

	ent.LoggerName = (ent.LoggerName + "          ")[:10] // Align topic/LoggerName spacing.

	if e.color {
		const green = uint8(32)
		ent.LoggerName = fmt.Sprintf("\x1b[%dm%s\x1b[0m", green, ent.LoggerName)
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
			const sep = "charon/" // TODO(corver): This only works if source built in a folder named 'charon'.
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
