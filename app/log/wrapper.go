// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package log

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/obolnetwork/charon/app/log/loki"
)

var _ zapLogger = multiLogger{}

// multiLogger wraps multiple zap loggers and implements zapLogger.
type multiLogger []zapLogger

func (m multiLogger) Debug(msg string, fields ...zap.Field) {
	for _, l := range m {
		l.Debug(msg, fields...)
	}
}

func (m multiLogger) Info(msg string, fields ...zap.Field) {
	for _, l := range m {
		l.Info(msg, fields...)
	}
}

func (m multiLogger) Warn(msg string, fields ...zap.Field) {
	for _, l := range m {
		l.Warn(msg, fields...)
	}
}

func (m multiLogger) Error(msg string, fields ...zap.Field) {
	for _, l := range m {
		l.Error(msg, fields...)
	}
}

// lokiWriter wraps a loki client and implements zap.SyncWriter.
type lokiWriter struct {
	cl *loki.Client
}

func (l lokiWriter) Write(line []byte) (n int, err error) {
	l.cl.Add(string(line))
	return len(line), nil
}

func (lokiWriter) Sync() error {
	return nil
}

func (m multiLogger) Core() zapcore.Core {
	var cores []zapcore.Core
	for _, l := range m {
		cores = append(cores, l.Core())
	}

	return zapcore.NewTee(cores...)
}
