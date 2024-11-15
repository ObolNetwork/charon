// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -run=TestMEVTest -update

func TestMEVTest(t *testing.T) {
	port1 := testutil.GetFreePort(t)
	endpoint1 := fmt.Sprintf("http://localhost:%v", port1)
	port2 := testutil.GetFreePort(t)
	endpoint2 := fmt.Sprintf("http://localhost:%v", port2)
	port3 := testutil.GetFreePort(t)
	endpoint3 := fmt.Sprintf("http://localhost:%v", port3)

	mockedMEVNode := StartHealthyMockedMEVNode(t)
	defer mockedMEVNode.Close()

	tests := []struct {
		name        string
		config      testMEVConfig
		expected    testCategoryResult
		expectedErr string
		cleanup     func(*testing.T, string)
	}{
		{
			name: "default scenario",
			config: testMEVConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    time.Minute,
				},
				Endpoints:          []string{mockedMEVNode.URL},
				BeaconNodeEndpoint: endpoint3,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					mockedMEVNode.URL: {
						{Name: "ping", Verdict: testVerdictOk, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "pingMeasure", Verdict: testVerdictGood, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "createBlock", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "createMultipleBlocks", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
				},
			},
			expectedErr: "",
		},
		{
			name: "connection refused",
			config: testMEVConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    time.Minute,
				},
				Endpoints:          []string{endpoint1, endpoint2},
				BeaconNodeEndpoint: endpoint3,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					endpoint1: {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
						{Name: "createBlock", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port3))}},
						{Name: "createMultipleBlocks", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port3))}},
					},
					endpoint2: {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
						{Name: "createBlock", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port3))}},
						{Name: "createMultipleBlocks", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port3))}},
					},
				},
			},
			expectedErr: "",
		},
		{
			name: "timeout",
			config: testMEVConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    100 * time.Nanosecond,
				},
				Endpoints:          []string{endpoint1, endpoint2},
				BeaconNodeEndpoint: endpoint3,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					endpoint1: {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errTimeoutInterrupted},
					},
					endpoint2: {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errTimeoutInterrupted},
					},
				},
			},
			expectedErr: "",
		},
		{
			name: "quiet",
			config: testMEVConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      true,
					TestCases:  nil,
					Timeout:    time.Minute,
				},
				Endpoints:          []string{endpoint1, endpoint2},
				BeaconNodeEndpoint: endpoint3,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					endpoint1: {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
						{Name: "createBlock", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port3))}},
						{Name: "createMultipleBlocks", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port3))}},
					},
					endpoint2: {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
						{Name: "createBlock", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port3))}},
						{Name: "createMultipleBlocks", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port3))}},
					},
				},
			},
			expectedErr: "",
		},
		{
			name: "unsupported test",
			config: testMEVConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  []string{"notSupportedTest"},
					Timeout:    time.Minute,
				},
				Endpoints:          []string{endpoint1, endpoint2},
				BeaconNodeEndpoint: endpoint3,
			},
			expected:    testCategoryResult{},
			expectedErr: "test case not supported",
		},
		{
			name: "custom test cases",
			config: testMEVConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  []string{"ping"},
					Timeout:    time.Minute,
				},
				Endpoints:          []string{endpoint1, endpoint2},
				BeaconNodeEndpoint: endpoint3,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					endpoint1: {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
					},
					endpoint2: {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
					},
				},
			},
			expectedErr: "",
		},
		{
			name: "write to file",
			config: testMEVConfig{
				testConfig: testConfig{
					OutputToml: "./write-to-file-test.toml.tmp",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    time.Minute,
				},
				Endpoints:          []string{endpoint1, endpoint2},
				BeaconNodeEndpoint: endpoint3,
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					endpoint1: {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
						{Name: "createBlock", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port3))}},
						{Name: "createMultipleBlocks", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port3))}},
					},
					endpoint2: {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
						{Name: "createBlock", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port3))}},
						{Name: "createMultipleBlocks", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port3))}},
					},
				},
				Score:        categoryScoreC,
				CategoryName: mevTestCategory,
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
			err := runTestMEV(ctx, &buf, test.config)
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

func StartHealthyMockedMEVNode(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func TestMEVTestFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectedErr string
	}{
		{
			name:        "default scenario",
			args:        []string{"mev", "--endpoints=\"test.endpoint\""},
			expectedErr: "",
		},
		{
			name:        "no endpoints flag",
			args:        []string{"mev"},
			expectedErr: "required flag(s) \"endpoints\" not set",
		},
		{
			name:        "no output toml on quiet",
			args:        []string{"mev", "--endpoints=\"test.endpoint\"", "--quiet"},
			expectedErr: "on --quiet, an --output-toml is required",
		},
		{
			name:        "no beacon node endpoint flag on load test",
			args:        []string{"mev", "--endpoints=\"test.endpoint\"", "--load-test"},
			expectedErr: "beacon-node-endpoint should be specified when load-test is",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := newAlphaCmd(newTestMEVCmd(func(context.Context, io.Writer, testMEVConfig) error { return nil }))
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
