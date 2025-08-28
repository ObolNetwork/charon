// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package errors provides errors with structured fields and stack traces.
// It is a drop-in replacement for stdlib errors and should be used as such throughout the app.
package errors

import (
	stderrors "errors" //nolint:revive // Allow import of stdlib errors package.
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

// NewSentinel returns a sentinel error that does not contain a stack trace. Sentinel errors are package level
// global variables so their creation stack traces do not add value. Sentinel errors should therefore always be wrapped
// when first returned to add proper stack trace.
//
// Usage:
//
//	var ErrNotFound = errors.NewSentinel("not found")
//
//	func check() error {
//	  ok := checkMap["foo"]
//	  if !ok {
//	    return errors.Wrap(ErrNotFound, "far not found")
//	  }
//	  return nil
//	}
//
//	func do() {
//	  err := foo()
//	  if errors.Is(err, ErrNotFound) {
//	    log.Error("Check not found", err) // This stack trace will be the one from the Wrap call, not the package level variable.
//	  }
//	}
func NewSentinel(msg string, fields ...z.Field) error {
	return structured{
		err:    stderrors.New(msg),
		fields: fields,
	}
}

// Wrap returns a new error wrapping the provided with additional structured fields and a stack trace if not already present.
func Wrap(err error, msg string, fields ...z.Field) error {
	return SkipWrap(err, msg, 2, fields...)
}

// SkipWrap is the same as Wrap, but allows overriding the skipped stacktraces.
func SkipWrap(err error, msg string, skip int, fields ...z.Field) error {
	var (
		stack zap.Field
		inner structured
	)
	if As(err, &inner) {
		fields = append(fields, inner.fields...) // Append inner fields
		stack = inner.stack                      // Use inner stack trace
	}

	if stack.Key == "" {
		stack = zap.StackSkip("stacktrace", skip) // Make new stack trace
	}

	return structured{
		err:    fmt.Errorf("%s: %w", msg, err), //nolint:forbidigo // Wrap error message using stdlib.
		fields: fields,
		stack:  stack,
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
