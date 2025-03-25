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

type DiskTestToolMock struct{}

func (DiskTestToolMock) CheckAvailability() error {
	return nil
}

func (DiskTestToolMock) WriteSpeed(context.Context, string, int) (float64, error) {
	return 100, nil
}

func (DiskTestToolMock) WriteIOPS(context.Context, string, int) (float64, error) {
	return 10, nil
}

func (DiskTestToolMock) ReadSpeed(context.Context, string, int) (float64, error) {
	return 100, nil
}

func (DiskTestToolMock) ReadIOPS(context.Context, string, int) (float64, error) {
	return 10, nil
}

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
					OutputJSON: "",
					Quiet:      false,
					TestCases:  []string{"AvailableMemory", "TotalMemory", "InternetLatency", "DiskWriteSpeed", "DiskWriteIOPS", "DiskReadSpeed", "DiskReadIOPS"},
					Timeout:    time.Minute,
				},
				DiskIOBlockSizeKb: 1,
				DiskTestTool:      DiskTestToolMock{},
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					"local": {
						{Name: "DiskWriteSpeed", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "DiskWriteIOPS", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "DiskReadSpeed", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "DiskReadIOPS", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "AvailableMemory", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "TotalMemory", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "InternetLatency", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
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
					OutputJSON: "",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    100 * time.Nanosecond,
				},
				DiskIOBlockSizeKb: 1,
				DiskTestTool:      DiskTestToolMock{},
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					"local": {
						{Name: "DiskWriteSpeed", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errTimeoutInterrupted},
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
					OutputJSON: "",
					Quiet:      true,
					TestCases:  []string{"AvailableMemory", "TotalMemory", "InternetLatency", "DiskWriteSpeed", "DiskWriteIOPS", "DiskReadSpeed", "DiskReadIOPS"},
					Timeout:    time.Minute,
				},
				DiskIOBlockSizeKb: 1,
				DiskTestTool:      DiskTestToolMock{},
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					"local": {
						{Name: "DiskWriteSpeed", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "DiskWriteIOPS", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "DiskReadSpeed", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "DiskReadIOPS", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "AvailableMemory", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "TotalMemory", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "InternetLatency", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
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
					OutputJSON: "",
					Quiet:      false,
					TestCases:  []string{"notSupportedTest"},
					Timeout:    time.Minute,
				},
				DiskIOBlockSizeKb: 1,
				DiskTestTool:      DiskTestToolMock{},
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
					OutputJSON: "",
					Quiet:      false,
					TestCases:  []string{"TotalMemory"},
					Timeout:    time.Minute,
				},
				DiskIOBlockSizeKb: 1,
				DiskTestTool:      DiskTestToolMock{},
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					"local": {
						{Name: "TotalMemory", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
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
					OutputJSON: "./write-to-file-test.json.tmp",
					Quiet:      false,
					TestCases:  []string{"AvailableMemory", "TotalMemory", "InternetLatency", "DiskWriteSpeed", "DiskWriteIOPS", "DiskReadSpeed", "DiskReadIOPS"},
					Timeout:    time.Minute,
				},
				DiskIOBlockSizeKb: 1,
				DiskTestTool:      DiskTestToolMock{},
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					"local": {
						{Name: "DiskWriteSpeed", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "DiskWriteIOPS", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "DiskReadSpeed", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "DiskReadIOPS", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "AvailableMemory", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "TotalMemory", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "InternetLatency", Verdict: testVerdictPoor, Measurement: "", Suggestion: "", Error: testResultError{}},
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
			_, err := runTestInfra(ctx, &buf, test.config)
			if test.expectedErr != "" {
				require.ErrorContains(t, err, test.expectedErr)
				return
			} else {
				require.NoError(t, err)
			}
			defer func() {
				if test.cleanup != nil {
					test.cleanup(t, test.config.OutputJSON)
				}
			}()

			if test.config.Quiet {
				require.Empty(t, buf.String())
			} else {
				testWriteOut(t, test.expected, buf)
			}

			if test.config.OutputJSON != "" {
				testWriteFile(t, test.expected, test.config.OutputJSON)
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
			name:        "no output json on quiet",
			args:        []string{"infra", "--disk-io-block-size-kb=1", "--quiet"},
			expectedErr: "on --quiet, an --output-json is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := newAlphaCmd(newTestInfraCmd(func(context.Context, io.Writer, testInfraConfig) (testCategoryResult, error) {
				return testCategoryResult{}, nil
			}))
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
