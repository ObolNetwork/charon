// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package errors_test

import (
	"io"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

// errPackageLevel mimics a sentinel error incorrectly declared with New instead of NewSentinel,
// capturing a stack trace at package initialisation.
var errPackageLevel = errors.New("package level")

// stackTrace returns the stack trace of the error.
func stackTrace(t *testing.T, err error) string {
	t.Helper()

	stacker, ok := err.(interface{ Stack() zap.Field })
	require.True(t, ok)

	return stacker.Stack().String
}

func TestWrapSentinelStack(t *testing.T) {
	// Wrapping a sentinel error provides the stack trace of the caller, since the sentinel has none.
	err := errors.Wrap(errors.NewSentinel("sentinel"), "wrapped")
	require.Contains(t, stackTrace(t, err), "TestWrapSentinelStack")

	// Wrapping an error that already has a stack trace retains it, so a package level error
	// declared with New keeps its useless initialisation stack trace.
	err = errors.Wrap(errPackageLevel, "wrapped")
	require.Contains(t, stackTrace(t, err), "errors_test.init")
	require.NotContains(t, stackTrace(t, err), "TestWrapSentinelStack")
}

func TestComparable(t *testing.T) {
	require.False(t, reflect.TypeOf(errors.New("x")).Comparable())
}

func TestIs(t *testing.T) {
	errX := errors.New("x")

	err1 := errors.New("1", z.Str("1", "1"))
	err11 := errors.Wrap(err1, "w1")
	err111 := errors.Wrap(err11, "w2")

	require.True(t, errors.Is(err1, err1))
	require.True(t, errors.Is(err11, err1))
	require.True(t, errors.Is(err111, err1))
	require.False(t, errors.Is(err1, err11))
	require.True(t, errors.Is(err11, err11))
	require.True(t, errors.Is(err111, err11))
	require.False(t, errors.Is(err1, err111))
	require.False(t, errors.Is(err11, err111))
	require.True(t, errors.Is(err111, err11))

	require.False(t, errors.Is(err111, errX))

	errIO1 := errors.Wrap(io.EOF, "w1")
	errIO11 := errors.Wrap(errIO1, "w1")

	require.True(t, errors.Is(io.EOF, io.EOF))
	require.True(t, errors.Is(errIO1, io.EOF))
	require.True(t, errors.Is(errIO11, io.EOF))
	require.False(t, errors.Is(io.EOF, errIO1))
	require.True(t, errors.Is(errIO1, errIO1))
	require.True(t, errors.Is(errIO11, errIO1))
	require.False(t, errors.Is(io.EOF, errIO11))
	require.False(t, errors.Is(errIO1, errIO11))
	require.True(t, errors.Is(errIO11, errIO11))
	require.False(t, errors.Is(err111, errX))
}
