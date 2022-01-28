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

// Package errors wraps github.com/pkg/errors and adds optional structured fields; similar to structured logging.
// See app/log/log_test.go for unit tests.
package errors

import (
	"fmt"

	pkgerrors "github.com/pkg/errors"
	"github.com/rs/zerolog"
)

// New returns a new error. Note that fields can be added to the resulting Error struct.
func New(msg string) Error {
	return Error{
		err: pkgerrors.New(msg),
	}
}

// Wrap returns an annotated error. Note that fields can be added to the resulting Error struct.
func Wrap(err error, msg string) Error {
	return Error{
		err: pkgerrors.Wrap(err, msg),
	}
}

// Error wraps a pkg/errors error with optional fields providing structured errors.
type Error struct {
	err    error
	fields []func(*zerolog.Array)
}

// Str adds the field key with val as a string to the sub-logger context.
func (e Error) Str(key, val string) Error {
	e.fields = append(e.fields, func(a *zerolog.Array) {
		a.Dict(zerolog.Dict().Str(key, val))
	})

	return e
}

// Stringer adds the field key with val.String() (or null if val is nil) to the sub-logger context.
func (e Error) Stringer(key string, val fmt.Stringer) Error {
	e.fields = append(e.fields, func(a *zerolog.Array) {
		a.Dict(zerolog.Dict().Stringer(key, val))
	})

	return e
}

// Bytes adds the field key with val as a []byte to the sub-logger context.
func (e Error) Bytes(key string, val []byte) Error {
	e.fields = append(e.fields, func(a *zerolog.Array) {
		a.Dict(zerolog.Dict().Bytes(key, val))
	})

	return e
}

// Hex adds the field key with val as a hex string to the sub-logger context.
func (e Error) Hex(key string, val []byte) Error {
	e.fields = append(e.fields, func(a *zerolog.Array) {
		a.Dict(zerolog.Dict().Hex(key, val))
	})

	return e
}

// Int adds the field key with i as an int to the sub-logger context.
func (e Error) Int(key string, i int) Error {
	e.fields = append(e.fields, func(a *zerolog.Array) {
		a.Dict(zerolog.Dict().Int(key, i))
	})

	return e
}

// Int64 adds the field key with i as a int64 to the sub-logger context.
func (e Error) Int64(key string, i int64) Error {
	e.fields = append(e.fields, func(a *zerolog.Array) {
		a.Dict(zerolog.Dict().Int64(key, i))
	})

	return e
}

// Uint64 adds the field key with i as an uint64 to the sub-logger context.
func (e Error) Uint64(key string, i uint64) Error {
	e.fields = append(e.fields, func(a *zerolog.Array) {
		a.Dict(zerolog.Dict().Uint64(key, i))
	})

	return e
}

func (e Error) Error() string {
	return e.err.Error()
}

func (e Error) ExtractFields(a *zerolog.Array) {
	for _, field := range e.fields {
		field(a)
	}

	var next Error
	if As(e.err, &next) {
		next.ExtractFields(a)
	}
}

func (e Error) MarshalZerologObject(ze *zerolog.Event) {
	a := zerolog.Arr()
	e.ExtractFields(a)
	ze.Array("fields", a)
	ze.Str("message", e.err.Error())
}

func (e Error) StackTrace() pkgerrors.StackTrace {
	type stackTracer interface {
		StackTrace() pkgerrors.StackTrace
	}

	//nolint:errorlint
	st, ok := pkgerrors.Cause(e.err).(stackTracer)
	if !ok {
		return nil
	}

	return st.StackTrace()
}

// Cause returns the underlying cause of the error and
// provides compatibility for pkg/error.Causer interface.
func (e Error) Cause() error {
	return e.err
}

// Unwrap returns the underlying error and
// provides compatibility for Go 1.13 error chains.
func (e Error) Unwrap() error {
	return e.err
}
