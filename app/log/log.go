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

// Package log provides global logging functions to be used throughout the charon app.
// It supports contextual logging via WithCtx and structured logging and structured errors
// via z.Field.
package log

import (
	"context"

	"go.uber.org/zap"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

type ctxKey struct{}

// WithCtx returns a copy of the context with which the logging fields are associated.
// Usage:
//
//  ctx := log.WithCtx(ctx, z.Int("slot", 1234))
//  ...
//  log.Info(ctx, "Slot processed") // Will contain field: slot=1234
//
func WithCtx(ctx context.Context, fields ...z.Field) context.Context {
	return context.WithValue(ctx, ctxKey{}, append(fields, fromCtx(ctx)...))
}

// WithTopic is a convenience function that adds the topic
// contextual logging field to the returned child context.
func WithTopic(ctx context.Context, component string) context.Context {
	return WithCtx(ctx, z.Str("topic", component))
}

func fromCtx(ctx context.Context) []z.Field {
	resp, _ := ctx.Value(ctxKey{}).([]z.Field)
	return resp
}

// Debug logs the message and fields (incl fields in the context) at Debug level.
// TODO(corver): Add indication of when debug should be used.
func Debug(ctx context.Context, msg string, fields ...z.Field) {
	logger.Debug(msg, unwrapDedup(ctx, fields...)...)
}

// Info logs the message and fields (incl fields in the context) at Info level.
// TODO(corver): Add indication of when info should be used.
func Info(ctx context.Context, msg string, fields ...z.Field) {
	logger.Info(msg, unwrapDedup(ctx, fields...)...)
}

// Warn logs the message and fields (incl fields in the context) at Warn level.
// TODO(corver): Add indication of when warn should be used.
func Warn(ctx context.Context, msg string, fields ...z.Field) {
	logger.Warn(msg, unwrapDedup(ctx, fields...)...)
}

// Error wraps err with msg and fields and logs it (incl fields in the context) at Error level.
// TODO(corver): Add indication of when error should be used.
func Error(ctx context.Context, msg string, err error, fields ...z.Field) {
	err = errors.Wrap(err, msg, fields...)
	logger.Error(err.Error(), unwrapDedup(ctx, errFields(err))...)
}

// unwrapDedup returns the wrapped zap fields from the slice and from the context. Duplicate fields are dropped.
func unwrapDedup(ctx context.Context, fields ...z.Field) []zap.Field {
	var resp []zap.Field
	dups := make(map[string]bool)
	adder := func(f zap.Field) {
		if dups[f.Key] {
			return
		}
		dups[f.Key] = true
		resp = append(resp, f)
	}

	for _, field := range fields {
		field(adder)
	}

	for _, field := range fromCtx(ctx) {
		field(adder)
	}

	return resp
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
	ferr, ok := err.(structErr) //nolint:errorlint
	if !ok {
		return func(add func(zap.Field)) {}
	}

	return func(add func(zap.Field)) {
		add(ferr.Stack())

		for _, field := range ferr.Fields() {
			field(add)
		}
	}
}
