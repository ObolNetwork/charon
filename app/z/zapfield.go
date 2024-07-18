// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package z provides an API for structured logging fields by wrapping zap.Field.
// It also supports internal structured errors.
package z

import (
	"fmt"
	"slices"

	"go.uber.org/zap"
)

// Field wraps one or more zap fields.
type Field func(add func(zap.Field))

// Fields returns the fields of an internal structured error.
func Fields(err error) []Field {
	type structErr interface {
		Fields() []Field
	}

	serr, ok := err.(structErr) //nolint:errorlint
	if !ok {
		return []Field{}
	}

	return serr.Fields()
}

// ContainsField returns true if the error contains the given field.
func ContainsField(err error, field Field) bool {
	fields := Fields(err)
	var targetField zap.Field
	field(func(zapField zap.Field) {
		targetField = zapField
	})

	return slices.ContainsFunc(fields, func(f Field) bool {
		var sourceField zap.Field
		f(func(zapField zap.Field) {
			sourceField = zapField
		})

		return targetField.Equals(sourceField)
	})
}

// Err returns a wrapped zap error field. It will include an additional stack trace and fields
// if the error is an internal structured error.
// NOTE: This is only used when logging errors on other levels than Error since it has built-in support for errors.
func Err(err error) Field {
	type structErr interface {
		Fields() []Field
		Stack() zap.Field
	}

	// Using cast instead of errors.As since no other wrapping library
	// is used and this avoids exporting the structured error type.
	serr, ok := err.(structErr) //nolint:errorlint
	if ok {
		return func(add func(zap.Field)) {
			add(zap.Error(err))
			add(serr.Stack())
			for _, field := range serr.Fields() {
				field(add)
			}
		}
	}

	return func(add func(zap.Field)) {
		add(zap.Error(err))
	}
}

// Str returns a wrapped zap string field.
func Str(key, val string) Field {
	return func(add func(zap.Field)) {
		add(zap.String(key, val))
	}
}

// Bool returns a wrapped zap boolean field.
func Bool(key string, val bool) Field {
	return func(add func(zap.Field)) {
		add(zap.Bool(key, val))
	}
}

// Int returns a wrapped zap int field.
func Int(key string, val int) Field {
	return func(add func(zap.Field)) {
		add(zap.Int(key, val))
	}
}

// Uint returns a wrapped zap uint field.
func Uint(key string, val uint) Field {
	return func(add func(zap.Field)) {
		add(zap.Uint(key, val))
	}
}

// I64 returns a wrapped zap int64 field.
func I64(key string, val int64) Field {
	return func(add func(zap.Field)) {
		add(zap.Int64(key, val))
	}
}

// U64 returns a wrapped zap uint64 field.
func U64(key string, val uint64) Field {
	return func(add func(zap.Field)) {
		add(zap.Uint64(key, val))
	}
}

// Hex returns a wrapped zap hex field.
func Hex(key string, val []byte) Field {
	return func(add func(zap.Field)) {
		add(zap.String(key, fmt.Sprintf("%#x", val)))
	}
}

// F64 returns a wrapped zap float64 field.
func F64(key string, val float64) Field {
	return func(add func(zap.Field)) {
		add(zap.Float64(key, val))
	}
}

// Any returns a wrapped zap string field with the string version of value.
// Note we are not using zap.Any since logfmt formatter doesn't support it.
func Any(key string, val any) Field {
	return func(add func(zap.Field)) {
		add(zap.String(key, fmt.Sprint(val)))
	}
}

// Skip is a noop wrapped zap field similar to zap.Skip.
var Skip = func(func(zap.Field)) {}
