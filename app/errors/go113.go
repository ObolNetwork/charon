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

//nolint:wrapcheck,revive
package errors

import (
	stderrors "errors"
)

// This file was copied from github.com/pkg/errors/go113.go. It ensures this package is compatible
// with the stdlib error package.

// Is reports whether any error in err's chain matches target.
//
// The chain consists of err itself followed by the sequence of errors obtained by
// repeatedly calling Unwrap.
//
// An error is considered to match a target if it is equal to that target or if
// it implements a method Is(error) bool such that Is(target) returns true.
func Is(err, target error) bool { return stderrors.Is(err, target) }

// As finds the first error in err's chain that matches target, and if so, sets
// target to that error value and returns true.
//
// The chain consists of err itself followed by the sequence of errors obtained by
// repeatedly calling Unwrap.
//
// An error matches target if the error's concrete value is assignable to the value
// pointed to by target, or if the error has a method As(interface{}) bool such that
// As(target) returns true. In the latter case, the As method is responsible for
// setting target.
//
// As will panic if target is not a non-nil pointer to either a type that implements
// error, or to any interface type. As returns false if err is nil.
func As(err error, target any) bool { return stderrors.As(err, target) }

// Unwrap returns the result of calling the Unwrap method on err, if err's
// type contains an Unwrap method returning error.
// Otherwise, Unwrap returns nil.
func Unwrap(err error) error {
	return stderrors.Unwrap(err)
}
