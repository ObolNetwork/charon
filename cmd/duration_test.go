// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cmd"
)

func TestDurationMarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		in          cmd.Duration
		expected    []byte
		expectedErr string
	}{
		{
			name:        "millisecond",
			in:          cmd.Duration{time.Millisecond},
			expected:    []byte("\"1ms\""),
			expectedErr: "",
		},
		{
			name:        "day",
			in:          cmd.Duration{24 * time.Hour},
			expected:    []byte("\"24h0m0s\""),
			expectedErr: "",
		},
		{
			name:        "1000 nanoseconds",
			in:          cmd.Duration{1000 * time.Nanosecond},
			expected:    []byte("\"1µs\""),
			expectedErr: "",
		},
		{
			name:        "60 seconds",
			in:          cmd.Duration{60 * time.Second},
			expected:    []byte("\"1m0s\""),
			expectedErr: "",
		},
		{
			name:        "empty",
			in:          cmd.Duration{},
			expected:    []byte("\"0s\""),
			expectedErr: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.in.MarshalJSON()
			if test.expectedErr != "" {
				require.ErrorContains(t, err, test.expectedErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.expected, res)
		})
	}
}

func TestDurationUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		in          []byte
		expected    cmd.Duration
		expectedErr string
	}{
		{
			name:        "millisecond",
			in:          []byte("\"1ms\""),
			expected:    cmd.Duration{time.Millisecond},
			expectedErr: "",
		},
		{
			name:        "day",
			in:          []byte("\"24h0m0s\""),
			expected:    cmd.Duration{24 * time.Hour},
			expectedErr: "",
		},
		{
			name:        "1000 nanoseconds",
			in:          []byte("\"1µs\""),
			expected:    cmd.Duration{1000 * time.Nanosecond},
			expectedErr: "",
		},
		{
			name:        "60 seconds",
			in:          []byte("\"1m0s\""),
			expected:    cmd.Duration{60 * time.Second},
			expectedErr: "",
		},
		{
			name:        "zero",
			in:          []byte("\"0s\""),
			expected:    cmd.Duration{},
			expectedErr: "",
		},
		{
			name:        "millisecond number",
			in:          []byte("1000000"),
			expected:    cmd.Duration{time.Millisecond},
			expectedErr: "",
		},
		{
			name:        "day number",
			in:          []byte("86400000000000"),
			expected:    cmd.Duration{24 * time.Hour},
			expectedErr: "",
		},
		{
			name:        "1000 nanoseconds number",
			in:          []byte("1000"),
			expected:    cmd.Duration{1000 * time.Nanosecond},
			expectedErr: "",
		},
		{
			name:        "60 seconds number",
			in:          []byte("60000000000"),
			expected:    cmd.Duration{60 * time.Second},
			expectedErr: "",
		},
		{
			name:        "zero number",
			in:          []byte("0"),
			expected:    cmd.Duration{},
			expectedErr: "",
		},
		{
			name:        "text string",
			in:          []byte("\"second\""),
			expected:    cmd.Duration{},
			expectedErr: "parse string time to duration",
		},
		{
			name:        "invalid json",
			in:          []byte("second"),
			expected:    cmd.Duration{},
			expectedErr: "unmarshal json duration",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res cmd.Duration

			err := res.UnmarshalJSON(test.in)
			if test.expectedErr != "" {
				require.ErrorContains(t, err, test.expectedErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.expected, res)
		})
	}
}

func TestDurationMarshalText(t *testing.T) {
	tests := []struct {
		name        string
		in          cmd.Duration
		expected    []byte
		expectedErr string
	}{
		{
			name:        "millisecond",
			in:          cmd.Duration{time.Millisecond},
			expected:    []byte("1ms"),
			expectedErr: "",
		},
		{
			name:        "day",
			in:          cmd.Duration{24 * time.Hour},
			expected:    []byte("24h0m0s"),
			expectedErr: "",
		},
		{
			name:        "1000 nanoseconds",
			in:          cmd.Duration{1000 * time.Nanosecond},
			expected:    []byte("1µs"),
			expectedErr: "",
		},
		{
			name:        "60 seconds",
			in:          cmd.Duration{60 * time.Second},
			expected:    []byte("1m0s"),
			expectedErr: "",
		},
		{
			name:        "empty",
			in:          cmd.Duration{},
			expected:    []byte("0s"),
			expectedErr: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.in.MarshalText()
			if test.expectedErr != "" {
				require.ErrorContains(t, err, test.expectedErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.expected, res)
		})
	}
}

func TestDurationUnmarshalText(t *testing.T) {
	tests := []struct {
		name        string
		in          []byte
		expected    cmd.Duration
		expectedErr string
	}{
		{
			name:        "millisecond",
			in:          []byte("1ms"),
			expected:    cmd.Duration{time.Millisecond},
			expectedErr: "",
		},
		{
			name:        "day",
			in:          []byte("24h0m0s"),
			expected:    cmd.Duration{24 * time.Hour},
			expectedErr: "",
		},
		{
			name:        "1000 nanoseconds",
			in:          []byte("1µs"),
			expected:    cmd.Duration{1000 * time.Nanosecond},
			expectedErr: "",
		},
		{
			name:        "60 seconds",
			in:          []byte("1m0s"),
			expected:    cmd.Duration{60 * time.Second},
			expectedErr: "",
		},
		{
			name:        "zero",
			in:          []byte("0s"),
			expected:    cmd.Duration{},
			expectedErr: "",
		},
		{
			name:        "millisecond number",
			in:          []byte("1000000"),
			expected:    cmd.Duration{time.Millisecond},
			expectedErr: "",
		},
		{
			name:        "day number",
			in:          []byte("86400000000000"),
			expected:    cmd.Duration{24 * time.Hour},
			expectedErr: "",
		},
		{
			name:        "1000 nanoseconds number",
			in:          []byte("1000"),
			expected:    cmd.Duration{1000 * time.Nanosecond},
			expectedErr: "",
		},
		{
			name:        "60 seconds number",
			in:          []byte("60000000000"),
			expected:    cmd.Duration{60 * time.Second},
			expectedErr: "",
		},
		{
			name:        "zero number",
			in:          []byte("0"),
			expected:    cmd.Duration{},
			expectedErr: "",
		},
		{
			name:        "text string",
			in:          []byte("second"),
			expected:    cmd.Duration{},
			expectedErr: "parse string time to duration",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res cmd.Duration

			err := res.UnmarshalText(test.in)
			if test.expectedErr != "" {
				require.ErrorContains(t, err, test.expectedErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.expected, res)
		})
	}
}

func TestRoundDuration(t *testing.T) {
	tests := []struct {
		name     string
		in       cmd.Duration
		expected cmd.Duration
	}{
		{
			name:     "15.151 milliseconds",
			in:       cmd.Duration{15151 * time.Microsecond},
			expected: cmd.Duration{15 * time.Millisecond},
		},
		{
			name:     "15.151515 milliseconds",
			in:       cmd.Duration{15151515 * time.Nanosecond},
			expected: cmd.Duration{15 * time.Millisecond},
		},
		{
			name:     "2.344444 seconds",
			in:       cmd.Duration{2344444 * time.Microsecond},
			expected: cmd.Duration{2340 * time.Millisecond},
		},
		{
			name:     "2.345555 seconds",
			in:       cmd.Duration{2345555 * time.Microsecond},
			expected: cmd.Duration{2350 * time.Millisecond},
		},
		{
			name:     "15.151 microsecond",
			in:       cmd.Duration{15151 * time.Nanosecond},
			expected: cmd.Duration{15 * time.Microsecond},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := cmd.RoundDuration(test.in)
			require.Equal(t, test.expected, res)
		})
	}
}
