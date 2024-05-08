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

//go:generate go test . -run=TestBeaconTest -update

func TestBeaconTest(t *testing.T) {
	port1 := testutil.GetFreePort(t)
	endpoint1 := fmt.Sprintf("http://localhost:%v", port1)
	port2 := testutil.GetFreePort(t)
	endpoint2 := fmt.Sprintf("http://localhost:%v", port2)

	mockedBeaconNode := StartHealthyMockedBeaconNode(t)
	defer mockedBeaconNode.Close()

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
				Endpoints: []string{mockedBeaconNode.URL},
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					mockedBeaconNode.URL: {
						{Name: "ping", Verdict: testVerdictOk, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "pingMeasure", Verdict: testVerdictGood, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "isSynced", Verdict: testVerdictOk, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "peerCount", Verdict: testVerdictGood, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
				},
			},
			expectedErr: "",
		},
		{
			name: "connection refused",
			config: testBeaconConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    time.Minute,
				},
				Endpoints: []string{endpoint1, endpoint2},
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					endpoint1: {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
						{Name: "isSynced", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
						{Name: "peerCount", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
					},
					endpoint2: {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
						{Name: "isSynced", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
						{Name: "peerCount", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
					},
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
					Timeout:    100 * time.Nanosecond,
				},
				Endpoints: []string{endpoint1, endpoint2},
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
			config: testBeaconConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      true,
					TestCases:  nil,
					Timeout:    time.Minute,
				},
				Endpoints: []string{endpoint1, endpoint2},
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					endpoint1: {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
						{Name: "isSynced", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
						{Name: "peerCount", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
					},
					endpoint2: {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
						{Name: "isSynced", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
						{Name: "peerCount", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
					},
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
				Endpoints: []string{endpoint1, endpoint2},
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
				Endpoints: []string{endpoint1, endpoint2},
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
			config: testBeaconConfig{
				testConfig: testConfig{
					OutputToml: "./write-to-file-test.toml.tmp",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    time.Minute,
				},
				Endpoints: []string{endpoint1, endpoint2},
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					endpoint1: {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
						{Name: "isSynced", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
						{Name: "peerCount", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
					},
					endpoint2: {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
						{Name: "isSynced", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
						{Name: "peerCount", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
					},
				},
				Score:        categoryScoreC,
				CategoryName: "beacon",
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

func StartHealthyMockedBeaconNode(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eth/v1/node/health":
		case "/eth/v1/node/syncing":
			_, err := w.Write([]byte(`{"data":{"head_slot":"0","sync_distance":"0","is_optimistic":false,"is_syncing":false}}`))
			require.NoError(t, err)
		case "/eth/v1/node/peers":
			_, err := w.Write([]byte(`{"meta":{"count":500}}`))
			require.NoError(t, err)
		}
		w.WriteHeader(http.StatusOK)
	}))
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
