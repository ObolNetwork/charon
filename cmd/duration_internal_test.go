// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDurationMarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		in          Duration
		expected    []byte
		expectedErr string
	}{
		{
			name:        "millisecond",
			in:          Duration{time.Millisecond},
			expected:    []byte("\"1ms\""),
			expectedErr: "",
		},
		{
			name:        "day",
			in:          Duration{24 * time.Hour},
			expected:    []byte("\"24h0m0s\""),
			expectedErr: "",
		},
		{
			name:        "1000 nanoseconds",
			in:          Duration{1000 * time.Nanosecond},
			expected:    []byte("\"1µs\""),
			expectedErr: "",
		},
		{
			name:        "60 seconds",
			in:          Duration{60 * time.Second},
			expected:    []byte("\"1m0s\""),
			expectedErr: "",
		},
		{
			name:        "empty",
			in:          Duration{},
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
		expected    Duration
		expectedErr string
	}{
		{
			name:        "millisecond",
			in:          []byte("\"1ms\""),
			expected:    Duration{time.Millisecond},
			expectedErr: "",
		},
		{
			name:        "day",
			in:          []byte("\"24h0m0s\""),
			expected:    Duration{24 * time.Hour},
			expectedErr: "",
		},
		{
			name:        "1000 nanoseconds",
			in:          []byte("\"1µs\""),
			expected:    Duration{1000 * time.Nanosecond},
			expectedErr: "",
		},
		{
			name:        "60 seconds",
			in:          []byte("\"1m0s\""),
			expected:    Duration{60 * time.Second},
			expectedErr: "",
		},
		{
			name:        "zero",
			in:          []byte("\"0s\""),
			expected:    Duration{},
			expectedErr: "",
		},
		{
			name:        "millisecond number",
			in:          []byte("1000000"),
			expected:    Duration{time.Millisecond},
			expectedErr: "",
		},
		{
			name:        "day number",
			in:          []byte("86400000000000"),
			expected:    Duration{24 * time.Hour},
			expectedErr: "",
		},
		{
			name:        "1000 nanoseconds number",
			in:          []byte("1000"),
			expected:    Duration{1000 * time.Nanosecond},
			expectedErr: "",
		},
		{
			name:        "60 seconds number",
			in:          []byte("60000000000"),
			expected:    Duration{60 * time.Second},
			expectedErr: "",
		},
		{
			name:        "zero number",
			in:          []byte("0"),
			expected:    Duration{},
			expectedErr: "",
		},
		{
			name:        "text string",
			in:          []byte("\"second\""),
			expected:    Duration{},
			expectedErr: "parse string time to duration",
		},
		{
			name:        "invalid json",
			in:          []byte("second"),
			expected:    Duration{},
			expectedErr: "unmarshal json duration",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res Duration
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
		in          Duration
		expected    []byte
		expectedErr string
	}{
		{
			name:        "millisecond",
			in:          Duration{time.Millisecond},
			expected:    []byte("1ms"),
			expectedErr: "",
		},
		{
			name:        "day",
			in:          Duration{24 * time.Hour},
			expected:    []byte("24h0m0s"),
			expectedErr: "",
		},
		{
			name:        "1000 nanoseconds",
			in:          Duration{1000 * time.Nanosecond},
			expected:    []byte("1µs"),
			expectedErr: "",
		},
		{
			name:        "60 seconds",
			in:          Duration{60 * time.Second},
			expected:    []byte("1m0s"),
			expectedErr: "",
		},
		{
			name:        "empty",
			in:          Duration{},
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
		expected    Duration
		expectedErr string
	}{
		{
			name:        "millisecond",
			in:          []byte("1ms"),
			expected:    Duration{time.Millisecond},
			expectedErr: "",
		},
		{
			name:        "day",
			in:          []byte("24h0m0s"),
			expected:    Duration{24 * time.Hour},
			expectedErr: "",
		},
		{
			name:        "1000 nanoseconds",
			in:          []byte("1µs"),
			expected:    Duration{1000 * time.Nanosecond},
			expectedErr: "",
		},
		{
			name:        "60 seconds",
			in:          []byte("1m0s"),
			expected:    Duration{60 * time.Second},
			expectedErr: "",
		},
		{
			name:        "zero",
			in:          []byte("0s"),
			expected:    Duration{},
			expectedErr: "",
		},
		{
			name:        "millisecond number",
			in:          []byte("1000000"),
			expected:    Duration{time.Millisecond},
			expectedErr: "",
		},
		{
			name:        "day number",
			in:          []byte("86400000000000"),
			expected:    Duration{24 * time.Hour},
			expectedErr: "",
		},
		{
			name:        "1000 nanoseconds number",
			in:          []byte("1000"),
			expected:    Duration{1000 * time.Nanosecond},
			expectedErr: "",
		},
		{
			name:        "60 seconds number",
			in:          []byte("60000000000"),
			expected:    Duration{60 * time.Second},
			expectedErr: "",
		},
		{
			name:        "zero number",
			in:          []byte("0"),
			expected:    Duration{},
			expectedErr: "",
		},
		{
			name:        "text string",
			in:          []byte("second"),
			expected:    Duration{},
			expectedErr: "parse string time to duration",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res Duration
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
