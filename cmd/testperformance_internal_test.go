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

//go:generate go test . -run=TestInfraTest -update

func TestInfraTest(t *testing.T) {
	tests := []struct {
		name        string
		config      testInfraConfig
		expected    testCategoryResult
		expectedErr string
		cleanup     func(*testing.T, string)
	}{
		{
			name: "default scenario",
			config: testInfraConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  []string{"availableMemory", "totalMemory", "internetLatency"},
					Timeout:    time.Minute,
				},
				DiskIOBlockSizeKb: 1,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					"local": {
						{Name: "availableMemory", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "totalMemory", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "internetLatency", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
				},
				Score:        categoryScoreC,
				CategoryName: infraTestCategory,
			},
			expectedErr: "",
		},
		{
			name: "timeout",
			config: testInfraConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    100 * time.Nanosecond,
				},
				DiskIOBlockSizeKb: 1,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					"local": {
						{Name: "diskWriteSpeed", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errTimeoutInterrupted},
					},
				},
				Score:        categoryScoreC,
				CategoryName: infraTestCategory,
			},
			expectedErr: "",
		},
		{
			name: "quiet",
			config: testInfraConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      true,
					TestCases:  []string{"availableMemory", "totalMemory", "internetLatency"},
					Timeout:    time.Minute,
				},
				DiskIOBlockSizeKb: 1,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					"local": {
						{Name: "availableMemory", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "totalMemory", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "internetLatency", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
				},
				Score:        categoryScoreC,
				CategoryName: infraTestCategory,
			},
			expectedErr: "",
		},
		{
			name: "unsupported test",
			config: testInfraConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  []string{"notSupportedTest"},
					Timeout:    time.Minute,
				},
				DiskIOBlockSizeKb: 1,
			},
			expected: testCategoryResult{
				Score:        categoryScoreC,
				CategoryName: infraTestCategory,
			},
			expectedErr: "test case not supported",
		},
		{
			name: "custom test cases",
			config: testInfraConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  []string{"totalMemory"},
					Timeout:    time.Minute,
				},
				DiskIOBlockSizeKb: 1,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					"local": {
						{Name: "totalMemory", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
				},
				Score:        categoryScoreC,
				CategoryName: infraTestCategory,
			},
			expectedErr: "",
		},
		{
			name: "write to file",
			config: testInfraConfig{
				testConfig: testConfig{
					OutputToml: "./write-to-file-test.toml.tmp",
					Quiet:      false,
					TestCases:  []string{"availableMemory", "totalMemory", "internetLatency"},
					Timeout:    time.Minute,
				},
				DiskIOBlockSizeKb: 1,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					"local": {
						{Name: "availableMemory", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "totalMemory", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "internetLatency", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
				},
				Score:        categoryScoreA,
				CategoryName: infraTestCategory,
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
			err := runTestInfra(ctx, &buf, test.config)
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

func StartHealthyInfraClient(t *testing.T, port int, ready chan bool) error {
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

func TestInfraTestFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectedErr string
	}{
		{
			name:        "default scenario",
			args:        []string{"infra", "--disk-io-block-size-kb=1"},
			expectedErr: "",
		},
		{
			name:        "no output toml on quiet",
			args:        []string{"infra", "--disk-io-block-size-kb=1", "--quiet"},
			expectedErr: "on --quiet, an --output-toml is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := newAlphaCmd(newTestInfraCmd(func(context.Context, io.Writer, testInfraConfig) error { return nil }))
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
