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

// Package z provides an API for structured logging fields by wrapping zap.Field.
// It also supports internal structured errors.
package z

import (
	"fmt"

	"go.uber.org/zap"
)

// Field wraps one or more zap fields.
type Field func(add func(zap.Field))

// Err returns a wrapped zap error field. It will include an additional stack trace and fields
// if the error is an internal structured error.
// Note: This is only used when logging errors on other levels than Error since it has built-in support for errors.
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

// Any returns a wrapped zap any field.
func Any(key string, val interface{}) Field {
	return func(add func(zap.Field)) {
		add(zap.Any(key, val))
	}
}

// Skip is a noop wrapped zap field similar to zap.Skip.
var Skip = func(add func(zap.Field)) {}
