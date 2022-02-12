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
		stack:  zap.StackSkip("stacktrace", 1),
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
