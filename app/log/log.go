// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package log provides global logging functions to be used throughout the charon app.
// It supports contextual logging via WithCtx and structured logging and structured errors
// via z.Field.
package log

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

type (
	ctxKey    struct{}
	topicKey  struct{}
	loggerKey struct{}
)

// WithCtx returns a copy of the context with which the logging fields are associated.
// Usage:
//
//	ctx := log.WithCtx(ctx, z.Int("slot", 1234))
//	...
//	log.Info(ctx, "Slot processed") // Will contain field: slot=1234
func WithCtx(ctx context.Context, fields ...z.Field) context.Context {
	return context.WithValue(ctx, ctxKey{}, append(fields, fieldsFromCtx(ctx)...))
}

// CopyFields returns a copy of the target with which the logging fields of the source context are associated.
func CopyFields(target context.Context, source context.Context) context.Context {
	return context.WithValue(target, ctxKey{}, fieldsFromCtx(source))
}

// WithTopic is a convenience function that adds the topic
// contextual logging field to the returned child context.
func WithTopic(ctx context.Context, component string) context.Context {
	ctx = context.WithValue(ctx, topicKey{}, component)
	return WithCtx(ctx, z.Str("topic", component))
}

// WithLogger returns a copy of the context with which the logger is associated replacing the default global logger.
func WithLogger(ctx context.Context, logger zapLogger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

func fieldsFromCtx(ctx context.Context) []z.Field {
	resp, ok := ctx.Value(ctxKey{}).([]z.Field)
	if !ok {
		return []z.Field{}
	}

	return resp
}

func metricsTopicFromCtx(ctx context.Context) string {
	resp, ok := ctx.Value(topicKey{}).(string)
	if resp == "" || !ok {
		return "unknown"
	}

	return resp
}

func getLogger(ctx context.Context) zapLogger {
	ctxLogger, ok := ctx.Value(loggerKey{}).(zapLogger)
	if ok {
		return ctxLogger
	}

	return logger
}

// Debug logs the message and fields (incl fields in the context) at Debug level.
// Debug should be used for most logging.
func Debug(ctx context.Context, msg string, fields ...z.Field) {
	zfl, ok := unwrapDedup(ctx, fields...)
	if !ok {
		return
	}

	trace.SpanFromContext(ctx).AddEvent("log.Debug: "+msg, toAttributes(zfl))
	getLogger(ctx).Debug(msg, zfl...)
}

// Info logs the message and fields (incl fields in the context) at Info level.
// Info should only be used for high level important events.
func Info(ctx context.Context, msg string, fields ...z.Field) {
	zfl, ok := unwrapDedup(ctx, fields...)
	if !ok {
		return
	}

	trace.SpanFromContext(ctx).AddEvent("log.Info: "+msg, toAttributes(zfl))
	getLogger(ctx).Info(msg, zfl...)
}

// Warn wraps err with msg and fields and logs it (incl fields in the context) at Warn level.
// Nil err is supported and results in similar behaviour to Info, just at Warn level.
// Warn should only be used when a problem is encountered that *does not* require any action to be taken.
func Warn(ctx context.Context, msg string, err error, fields ...z.Field) {
	incWarnCounter(ctx)

	if err == nil {
		zfl, ok := unwrapDedup(ctx, fields...)
		if !ok {
			return
		}

		trace.SpanFromContext(ctx).AddEvent("log.Warn: "+msg, toAttributes(zfl))
		getLogger(ctx).Warn(msg, zfl...)

		return
	}

	err = errors.SkipWrap(err, msg, 2, fields...)

	zfl, ok := unwrapDedup(ctx, errFields(err))
	if !ok {
		return
	}

	trace.SpanFromContext(ctx).RecordError(err, trace.WithStackTrace(true), toAttributes(zfl))
	getLogger(ctx).Warn(err.Error(), zfl...)
}

// Error wraps err with msg and fields and logs it (incl fields in the context) at Error level.
// Nil err is supported and results in similar behaviour to Info, just at Error level.
// Error should only be used when a problem is encountered that *does* require action to be taken.
func Error(ctx context.Context, msg string, err error, fields ...z.Field) {
	incErrorCounter(ctx)

	if err == nil {
		zfl, ok := unwrapDedup(ctx, fields...)
		if !ok {
			return
		}

		trace.SpanFromContext(ctx).AddEvent("log.Error: "+msg, toAttributes(zfl))
		getLogger(ctx).Error(msg, zfl...)

		return
	}

	err = errors.SkipWrap(err, msg, 2, fields...)

	zfl, ok := unwrapDedup(ctx, errFields(err))
	if !ok {
		return
	}

	trace.SpanFromContext(ctx).RecordError(err, trace.WithStackTrace(true), toAttributes(zfl))
	getLogger(ctx).Error(err.Error(), zfl...)
}

// unwrapDedup returns true and the wrapped zap fields from the slice and from the context. Duplicate fields are dropped.
// It returns false if the whole log should be filtered out (dropped).
func unwrapDedup(ctx context.Context, fields ...z.Field) ([]zap.Field, bool) {
	var (
		resp     []zap.Field
		filtered bool
		dups     = make(map[string]bool)
	)

	adder := func(f zap.Field) {
		if f.Type == filterFieldType {
			filtered = true
			return
		}

		if dups[f.Key] {
			return
		}

		dups[f.Key] = true
		resp = append(resp, f)
	}

	for _, field := range fields {
		field(adder)
	}

	for _, field := range fieldsFromCtx(ctx) {
		field(adder)
	}

	return resp, !filtered
}

// errFields is similar to z.Err and returns the structured error fields and
// stack trace but without the error message. It avoids duplication of the error message
// since it is used as the main log message in Error above.
func errFields(err error) z.Field {
	type structErr interface {
		Fields() []z.Field
		Stack() zap.Field
	}

	// Using cast instead of errors.As since no other wrapping library
	// is used and this avoids exporting the structured error type.
	ferr, ok := err.(structErr)
	if !ok {
		return func(func(zap.Field)) {}
	}

	return func(add func(zap.Field)) {
		add(ferr.Stack())

		for _, field := range ferr.Fields() {
			field(add)
		}
	}
}

// toAttributes returns the zap fields as tracing event attributes.
func toAttributes(fields []zap.Field) trace.EventOption {
	var kvs []attribute.KeyValue

	for _, field := range fields {
		if field.Interface != nil {
			kvs = append(kvs, attribute.String(field.Key, fmt.Sprint(field.Interface)))
		} else if field.String != "" {
			kvs = append(kvs, attribute.String(field.Key, field.String))
		} else if field.Integer != 0 {
			kvs = append(kvs, attribute.Int64(field.Key, field.Integer))
		}
	}

	return trace.WithAttributes(kvs...)
}
