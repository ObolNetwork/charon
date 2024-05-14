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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -run=TestValidatorTest -update

func TestValidatorTest(t *testing.T) {
	port := testutil.GetFreePort(t)
	readyChan := make(chan bool)
	go func() {
		err := StartHealthyValidatorClient(t, port, readyChan)
		assert.NoError(t, err)
	}()
	<-readyChan
	validatorAPIAddress := fmt.Sprintf("127.0.0.1:%v", port)

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
					Timeout:    time.Minute,
				},
				APIAddress: validatorAPIAddress,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					validatorAPIAddress: {
						{Name: "ping", Verdict: testVerdictOk, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "pingMeasure", Verdict: testVerdictGood, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "pingLoad", Verdict: testVerdictGood, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
				},
				Score:        categoryScoreA,
				CategoryName: "validator",
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
					Timeout:    100 * time.Nanosecond,
				},
				APIAddress: validatorAPIAddress,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					validatorAPIAddress: {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errTimeoutInterrupted},
					},
				},
				Score:        categoryScoreC,
				CategoryName: "validator",
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
					Timeout:    time.Minute,
				},
				APIAddress: validatorAPIAddress,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					validatorAPIAddress: {
						{Name: "ping", Verdict: testVerdictOk, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "pingMeasure", Verdict: testVerdictGood, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "pingLoad", Verdict: testVerdictGood, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
				},
				Score:        categoryScoreA,
				CategoryName: "validator",
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
					Timeout:    time.Minute,
				},
				APIAddress: validatorAPIAddress,
			},
			expected: testCategoryResult{
				Score:        categoryScoreC,
				CategoryName: "validator",
			},
			expectedErr: "test case not supported",
		},
		{
			name: "custom test cases",
			config: testValidatorConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  []string{"ping"},
					Timeout:    time.Minute,
				},
				APIAddress: validatorAPIAddress,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					validatorAPIAddress: {
						{Name: "ping", Verdict: testVerdictOk, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
				},
				Score:        categoryScoreA,
				CategoryName: "validator",
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
					Timeout:    time.Minute,
				},
				APIAddress: validatorAPIAddress,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					validatorAPIAddress: {
						{Name: "ping", Verdict: testVerdictOk, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "pingMeasure", Verdict: testVerdictGood, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "pingLoad", Verdict: testVerdictGood, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
				},
				Score:        categoryScoreA,
				CategoryName: "validator",
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
				testWriteOut(t, test.expected, buf)
			}

			if test.config.OutputToml != "" {
				testWriteFile(t, test.expected, test.config.OutputToml)
			}
		})
	}
}

func StartHealthyValidatorClient(t *testing.T, port int, ready chan bool) error {
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

func TestValidatorTestFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectedErr string
	}{
		{
			name:        "default scenario",
			args:        []string{"validator", "--validator-api-address=\"test.endpoint\""},
			expectedErr: "",
		},
		{
			name:        "no output toml on quiet",
			args:        []string{"validator", "--validator-api-address=\"test.endpoint\"", "--quiet"},
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
