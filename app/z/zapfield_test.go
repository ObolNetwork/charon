// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package z_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

func TestFields(t *testing.T) {
	err := errors.New("test", z.Str("foo", "bar"), z.I64("zet", 123))

	fields := z.Fields(err)

	require.Len(t, fields, 2)
	require.NotNil(t, fields[0])
	require.NotNil(t, fields[1])
}

func TestContainsField(t *testing.T) {
	f1 := z.Str("foo", "bar")
	f2 := z.I64("zet", 123)
	err := errors.New("test", f1, f2)

	require.True(t, z.ContainsField(err, f1))
	require.True(t, z.ContainsField(err, f2))
	require.False(t, z.ContainsField(err, z.Bool("bool", true)))
}

func TestErr(t *testing.T) {
	err := errors.New("test", z.Str("foo", "bar"), z.I64("zet", 123))

	field := z.Err(err)

	ufs := unwrap(field)
	require.Len(t, ufs, 4) // zap.Error, zap.Stack, foo, zet
	require.True(t, slices.ContainsFunc(ufs, func(f zap.Field) bool {
		return f.Equals(zap.String("foo", "bar"))
	}))
	require.True(t, slices.ContainsFunc(ufs, func(f zap.Field) bool {
		return f.Equals(zap.Int64("zet", 123))
	}))
	require.True(t, slices.ContainsFunc(ufs, func(f zap.Field) bool {
		return f.Key == "stacktrace"
	}))
	require.True(t, slices.ContainsFunc(ufs, func(f zap.Field) bool {
		return f.Key == "error"
	}))
}

func TestStr(t *testing.T) {
	field := z.Str("foo", "bar")

	ufs := unwrap(field)
	require.Len(t, ufs, 1)
	require.True(t, ufs[0].Equals(zap.String("foo", "bar")))
}

func TestBool(t *testing.T) {
	field := z.Bool("foo", true)

	ufs := unwrap(field)
	require.Len(t, ufs, 1)
	require.True(t, ufs[0].Equals(zap.Bool("foo", true)))
}

func TestI64(t *testing.T) {
	field := z.I64("foo", 123)

	ufs := unwrap(field)
	require.Len(t, ufs, 1)
	require.True(t, ufs[0].Equals(zap.Int64("foo", 123)))
}

func TestU64(t *testing.T) {
	field := z.U64("foo", 123)

	ufs := unwrap(field)
	require.Len(t, ufs, 1)
	require.True(t, ufs[0].Equals(zap.Uint64("foo", 123)))
}

func TestInt(t *testing.T) {
	field := z.Int("foo", 123)

	ufs := unwrap(field)
	require.Len(t, ufs, 1)
	require.True(t, ufs[0].Equals(zap.Int("foo", 123)))
}

func TestUint(t *testing.T) {
	field := z.Uint("foo", 123)

	ufs := unwrap(field)
	require.Len(t, ufs, 1)
	require.True(t, ufs[0].Equals(zap.Uint("foo", 123)))
}

func TestF64(t *testing.T) {
	field := z.F64("foo", 123.45)

	ufs := unwrap(field)
	require.Len(t, ufs, 1)
	require.True(t, ufs[0].Equals(zap.Float64("foo", 123.45)))
}

func TestAny(t *testing.T) {
	field := z.Any("foo", 123.45)

	ufs := unwrap(field)
	require.Len(t, ufs, 1)
	require.True(t, ufs[0].Equals(zap.String("foo", "123.45")))
}

func TestSkip(t *testing.T) {
	ufs := unwrap(z.Skip)
	require.Empty(t, ufs)
}

func unwrap(fields ...z.Field) []zap.Field {
	var resp []zap.Field

	adder := func(f zap.Field) {
		resp = append(resp, f)
	}

	for _, field := range fields {
		field(adder)
	}

	return resp
}
