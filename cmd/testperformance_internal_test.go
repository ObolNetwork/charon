// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
)

//go:generate go test . -run=TestPerformanceTest -update

func TestPerformanceTest(t *testing.T) {
	tests := []struct {
		name        string
		config      testPerformanceConfig
		expected    testCategoryResult
		expectedErr string
		cleanup     func(*testing.T, string)
	}{
		{
			name: "default scenario",
			config: testPerformanceConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  []string{"diskWrite", "availableMemory", "totalMemory", "internetLatency"},
					Timeout:    time.Minute,
				},
				DiskWriteMB: 1,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					"local": {
						{Name: "diskWrite", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "availableMemory", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "totalMemory", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "internetLatency", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
				},
				Score:        categoryScoreC,
				CategoryName: performanceTestCategory,
			},
			expectedErr: "",
		},
		{
			name: "timeout",
			config: testPerformanceConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    100 * time.Nanosecond,
				},
				DiskWriteMB: 1,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					"local": {
						{Name: "diskWrite", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errTimeoutInterrupted},
					},
				},
				Score:        categoryScoreC,
				CategoryName: performanceTestCategory,
			},
			expectedErr: "",
		},
		{
			name: "quiet",
			config: testPerformanceConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      true,
					TestCases:  []string{"diskWrite", "availableMemory", "totalMemory", "internetLatency"},
					Timeout:    time.Minute,
				},
				DiskWriteMB: 1,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					"local": {
						{Name: "diskWrite", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "availableMemory", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "totalMemory", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "internetLatency", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
				},
				Score:        categoryScoreC,
				CategoryName: performanceTestCategory,
			},
			expectedErr: "",
		},
		{
			name: "unsupported test",
			config: testPerformanceConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  []string{"notSupportedTest"},
					Timeout:    time.Minute,
				},
				DiskWriteMB: 1,
			},
			expected: testCategoryResult{
				Score:        categoryScoreC,
				CategoryName: performanceTestCategory,
			},
			expectedErr: "test case not supported",
		},
		{
			name: "custom test cases",
			config: testPerformanceConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  []string{"diskWrite"},
					Timeout:    time.Minute,
				},
				DiskWriteMB: 1,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					"local": {
						{Name: "diskWrite", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
				},
				Score:        categoryScoreC,
				CategoryName: performanceTestCategory,
			},
			expectedErr: "",
		},
		{
			name: "write to file",
			config: testPerformanceConfig{
				testConfig: testConfig{
					OutputToml: "./write-to-file-test.toml.tmp",
					Quiet:      false,
					TestCases:  []string{"diskWrite", "availableMemory", "totalMemory", "internetLatency"},
					Timeout:    time.Minute,
				},
				DiskWriteMB: 1,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					"local": {
						{Name: "diskWrite", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "availableMemory", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "totalMemory", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "internetLatency", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
				},
				Score:        categoryScoreC,
				CategoryName: performanceTestCategory,
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
			err := runTestPerformance(ctx, &buf, test.config)
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

func StartHealthyPerformanceClient(t *testing.T, port int, ready chan bool) error {
	t.Helper()
	defer close(ready)

	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%v", port))
	if err != nil {
		return errors.Wrap(err, "net listen")
	}
	defer listener.Close()

	ready <- true
	for {
		_, err := listener.Accept()
		if err != nil {
			return errors.Wrap(err, "listener accept")
		}
	}
}

func TestPerformanceTestFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectedErr string
	}{
		{
			name:        "default scenario",
			args:        []string{"performance", "--disk-write-mb=1"},
			expectedErr: "",
		},
		{
			name:        "no output toml on quiet",
			args:        []string{"performance", "--disk-write-mb=1", "--quiet"},
			expectedErr: "on --quiet, an --output-toml is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := newAlphaCmd(newTestPerformanceCmd(func(context.Context, io.Writer, testPerformanceConfig) error { return nil }))
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
