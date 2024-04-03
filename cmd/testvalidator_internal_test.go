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

//go:generate go test . -run=TestValidatorTest -update

func TestValidatorTest(t *testing.T) {
	tests := []struct {
		name        string
		config      testValidatorConfig
		expected    testCategoryResult
		expectedErr string
		cleanup     func(*testing.T, string)
	}{
		{
			name: "default scenario",
			config: testValidatorConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    24 * time.Hour,
				},
				APIAddress: "",
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
			config: testValidatorConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    time.Nanosecond,
				},
				APIAddress: "",
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
			config: testValidatorConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      true,
					TestCases:  nil,
					Timeout:    24 * time.Hour,
				},
				APIAddress: "",
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
			config: testValidatorConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  []string{"notSupportedTest"},
					Timeout:    24 * time.Hour,
				},
				APIAddress: "",
			},
			expected:    testCategoryResult{},
			expectedErr: "test case not supported",
		},
		{
			name: "custom test cases",
			config: testValidatorConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  []string{"ping"},
					Timeout:    24 * time.Hour,
				},
				APIAddress: "",
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
			config: testValidatorConfig{
				testConfig: testConfig{
					OutputToml: "./write-to-file-test.toml.tmp",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    24 * time.Hour,
				},
				APIAddress: "",
			},
			expected: testCategoryResult{
				CategoryName: "validator",
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
			err := runTestValidator(ctx, &buf, test.config)
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

func TestValidatorTestFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectedErr string
	}{
		{
			name:        "default scenario",
			args:        []string{"validator", "--api-address=\"test.endpoint\""},
			expectedErr: "",
		},
		{
			name:        "no output toml on quiet",
			args:        []string{"validator", "--api-address=\"test.endpoint\"", "--quiet"},
			expectedErr: "on --quiet, an --output-toml is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := newAlphaCmd(newTestValidatorCmd(func(context.Context, io.Writer, testValidatorConfig) error { return nil }))
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
