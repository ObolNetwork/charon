// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

//go:generate go test . -run=TestBeaconTest -update

//nolint:dupl // code is marked as duplicate currently, as we are testing the same test skeleton, ignore for now
func TestBeaconTest(t *testing.T) {
	tests := []struct {
		name        string
		config      testBeaconConfig
		expected    testCategoryResult
		expectedErr string
		cleanup     func(*testing.T, string)
	}{
		{
			name: "default scenario",
			config: testBeaconConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    time.Minute,
				},
				Endpoints: []string{"beacon-endpoint-1", "beacon-endpoint-2"},
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					"beacon-endpoint-1": {{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errNotImplemented}},
					"beacon-endpoint-2": {{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errNotImplemented}},
				},
			},
			expectedErr: "",
		},
		{
			name: "timeout",
			config: testBeaconConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    time.Nanosecond,
				},
				Endpoints: []string{"beacon-endpoint-1", "beacon-endpoint-2"},
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					"beacon-endpoint-1": {{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errTimeoutInterrupted}},
					"beacon-endpoint-2": {{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errTimeoutInterrupted}},
				},
			},
			expectedErr: "",
		},
		{
			name: "quiet",
			config: testBeaconConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      true,
					TestCases:  nil,
					Timeout:    time.Minute,
				},
				Endpoints: []string{"beacon-endpoint-1", "beacon-endpoint-2"},
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					"beacon-endpoint-1": {{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errNotImplemented}},
					"beacon-endpoint-2": {{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errNotImplemented}},
				},
			},
			expectedErr: "",
		},
		{
			name: "unsupported test",
			config: testBeaconConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  []string{"notSupportedTest"},
					Timeout:    time.Minute,
				},
				Endpoints: []string{"beacon-endpoint-1", "beacon-endpoint-2"},
			},
			expected:    testCategoryResult{},
			expectedErr: "test case not supported",
		},
		{
			name: "custom test cases",
			config: testBeaconConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  []string{"ping"},
					Timeout:    time.Minute,
				},
				Endpoints: []string{"beacon-endpoint-1", "beacon-endpoint-2"},
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					"beacon-endpoint-1": {{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errNotImplemented}},
					"beacon-endpoint-2": {{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errNotImplemented}},
				},
			},
			expectedErr: "",
		},

		{
			name: "write to file",
			config: testBeaconConfig{
				testConfig: testConfig{
					OutputToml: "./write-to-file-test.toml.tmp",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    time.Minute,
				},
				Endpoints: []string{"beacon-endpoint-1", "beacon-endpoint-2"},
			},
			expected: testCategoryResult{
				CategoryName: "beacon",
				Targets: map[string][]testResult{
					"beacon-endpoint-1": {{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errNotImplemented}},
					"beacon-endpoint-2": {{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errNotImplemented}},
				},
				Score: categoryScoreC,
			},
			expectedErr: "",
			cleanup: func(t *testing.T, p string) {
				t.Helper()
				err := os.Remove(p)
				require.NoError(t, err)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buf bytes.Buffer
			ctx := context.Background()
			err := runTestBeacon(ctx, &buf, test.config)
			if test.expectedErr != "" {
				require.ErrorContains(t, err, test.expectedErr)
				return
			} else {
				require.NoError(t, err)
			}
			defer func() {
				if test.cleanup != nil {
					test.cleanup(t, test.config.OutputToml)
				}
			}()

			if test.config.Quiet {
				require.Empty(t, buf.String())
			} else {
				testWriteOut(t, test.expected, buf)
			}

			if test.config.OutputToml != "" {
				testWriteFile(t, test.expected, test.config.OutputToml)
			}
		})
	}
}

func TestBeaconTestFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectedErr string
	}{
		{
			name:        "default scenario",
			args:        []string{"beacon", "--endpoints=\"test.endpoint\""},
			expectedErr: "",
		},
		{
			name:        "no endpoints flag",
			args:        []string{"beacon"},
			expectedErr: "required flag(s) \"endpoints\" not set",
		},
		{
			name:        "no output toml on quiet",
			args:        []string{"beacon", "--endpoints=\"test.endpoint\"", "--quiet"},
			expectedErr: "on --quiet, an --output-toml is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := newAlphaCmd(newTestBeaconCmd(func(context.Context, io.Writer, testBeaconConfig) error { return nil }))
			cmd.SetArgs(test.args)
			err := cmd.Execute()
			if test.expectedErr != "" {
				require.ErrorContains(t, err, test.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
