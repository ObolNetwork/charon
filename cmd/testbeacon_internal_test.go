// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
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
					Timeout:    24 * time.Hour,
				},
				Endpoints: []string{},
			},
			expected: testCategoryResult{
				TestsExecuted: map[string]testResult{
					"ping": {Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "not implemented"},
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
				Endpoints: []string{},
			},
			expected: testCategoryResult{
				TestsExecuted: map[string]testResult{
					"ping": {Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: ""},
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
					Timeout:    24 * time.Hour,
				},
				Endpoints: []string{},
			},
			expected: testCategoryResult{
				TestsExecuted: map[string]testResult{
					"ping": {Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "not implemented"},
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
					Timeout:    24 * time.Hour,
				},
				Endpoints: []string{},
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
					Timeout:    24 * time.Hour,
				},
				Endpoints: []string{},
			},
			expected: testCategoryResult{
				TestsExecuted: map[string]testResult{
					"ping": {Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "not implemented"},
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
					Timeout:    24 * time.Hour,
				},
				Endpoints: []string{},
			},
			expected: testCategoryResult{
				CategoryName: "beacon",
				TestsExecuted: map[string]testResult{
					"ping": {Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "not implemented"},
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
				testWriteOut(t, test.expected.TestsExecuted, buf)
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

func testWriteOut(t *testing.T, expectedTests map[string]testResult, buf bytes.Buffer) {
	t.Helper()
	bufTests := strings.Split(buf.String(), "\n")
	bufTests = slices.Delete(bufTests, 0, 8)
	bufTests = slices.Delete(bufTests, len(bufTests)-4, len(bufTests))

	require.Equal(t, len(bufTests), len(expectedTests))

	for _, bt := range bufTests {
		name, res, exist := strings.Cut(bt, " ")
		require.True(t, exist)
		require.Contains(t, res, expectedTests[name].Verdict)
		require.Contains(t, res, expectedTests[name].Measurement)
		require.Contains(t, res, expectedTests[name].Suggestion)
		require.Contains(t, res, expectedTests[name].Error)
	}
}

func testWriteFile(t *testing.T, expectedRes testCategoryResult, path string) {
	t.Helper()
	file, err := os.ReadFile(path)
	require.NoError(t, err)
	var res testCategoryResult
	err = toml.Unmarshal(file, &res)
	require.NoError(t, err)

	require.Equal(t, expectedRes.CategoryName, res.CategoryName)
	require.Equal(t, expectedRes.Score, res.Score)
	require.Equal(t, len(expectedRes.TestsExecuted), len(res.TestsExecuted))
	for testName, testRes := range res.TestsExecuted {
		require.Equal(t, expectedRes.TestsExecuted[testName].Verdict, testRes.Verdict)
		require.Equal(t, expectedRes.TestsExecuted[testName].Measurement, testRes.Measurement)
		require.Equal(t, expectedRes.TestsExecuted[testName].Suggestion, testRes.Suggestion)
		require.Equal(t, expectedRes.TestsExecuted[testName].Error, testRes.Error)
	}
}
