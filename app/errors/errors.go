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

// Package errors provides errors with structured fields and stack traces.
// It is a drop-in replacement for stdlib errors and should be used as such throughout the app.
package errors

import (
	// nolint:revive
	stderrors "errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/obolnetwork/charon/app/z"
)

// New returns an error that formats as the given text and contains the structured fields and a stack trace.
func New(msg string, fields ...z.Field) error {
	return structured{
		err:    stderrors.New(msg),
		fields: fields,
		stack:  zap.StackSkip("stacktrace", 1),
	}
}

// Wrap returns a new error wrapping the provided with additional structured fields and a stack trace if not already present.
func Wrap(err error, msg string, fields ...z.Field) error {
	return SkipWrap(err, msg, 2, fields...)
}

// SkipWrap is the same as Wrap, but allows overriding the skipped stacktraces.
func SkipWrap(err error, msg string, skip int, fields ...z.Field) error {
	wrap := fmt.Errorf("%s: %w", msg, err)

	var inner structured
	if As(err, &inner) {
		return structured{
			err:    wrap,
			fields: append(fields, inner.fields...),
			stack:  inner.stack,
		}
	}

	return structured{
		err:    wrap,
		fields: fields,
		stack:  zap.StackSkip("stacktrace", skip),
	}
}

// structured is the implementation of a structured error.
type structured struct {
	err    error
	fields []z.Field
	stack  zap.Field
}

// Error returns the error message and implements the error interface.
func (s structured) Error() string {
	return s.err.Error()
}

// Fields returns the structured fields.
func (s structured) Fields() []z.Field {
	return s.fields
}

// Stack returns the zap stack trace.
func (s structured) Stack() zap.Field {
	return s.stack
}

// Unwrap returns the underlying error and
// provides compatibility with stdlib errors.
func (s structured) Unwrap() error {
	return s.err
}

// Is returns true if err is equaled to this structured error.
func (s structured) Is(err error) bool {
	var other structured
	if !stderrors.As(err, &other) {
		return false
	}

	return stderrors.Is(s.err, other.err)
}
