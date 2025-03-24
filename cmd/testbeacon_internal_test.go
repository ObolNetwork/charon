// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

	mockedBeaconNode := startHealthyMockedBeaconNode(t)
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
					OutputJSON: "",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    time.Minute,
				},
				Endpoints: []string{mockedBeaconNode.URL},
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					mockedBeaconNode.URL: {
						{Name: "Ping", Verdict: testVerdictOk, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "PingMeasure", Verdict: testVerdictGood, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "Version", Verdict: testVerdictOk, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "Synced", Verdict: testVerdictOk, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "PeerCount", Verdict: testVerdictGood, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "PingLoad", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "Simulate1", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "Simulate10", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "Simulate100", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "Simulate500", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "Simulate1000", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "SimulateCustom", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
				},
			},
			expectedErr: "",
		},
		{
			name: "connection refused",
			config: testBeaconConfig{
				testConfig: testConfig{
					OutputJSON: "",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    time.Minute,
				},
				Endpoints: []string{endpoint1, endpoint2},
			},
			expected: testCategoryResult{
				Targets: defaultFailingBNTests(t, endpoint1, endpoint2, port1, port2),
			},
			expectedErr: "",
		},
		{
			name: "timeout",
			config: testBeaconConfig{
				testConfig: testConfig{
					OutputJSON: "",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    100 * time.Microsecond,
				},
				Endpoints: []string{endpoint1, endpoint2},
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					endpoint1: {
						{Name: "Ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errTimeoutInterrupted},
					},
					endpoint2: {
						{Name: "Ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errTimeoutInterrupted},
					},
				},
			},
			expectedErr: "",
		},
		{
			name: "quiet",
			config: testBeaconConfig{
				testConfig: testConfig{
					OutputJSON: "",
					Quiet:      true,
					TestCases:  nil,
					Timeout:    time.Minute,
				},
				Endpoints: []string{endpoint1, endpoint2},
			},
			expected: testCategoryResult{
				Targets: defaultFailingBNTests(t, endpoint1, endpoint2, port1, port2),
			},
			expectedErr: "",
		},
		{
			name: "unsupported test",
			config: testBeaconConfig{
				testConfig: testConfig{
					OutputJSON: "",
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
					OutputJSON: "",
					Quiet:      false,
					TestCases:  []string{"Ping"},
					Timeout:    time.Minute,
				},
				Endpoints: []string{endpoint1, endpoint2},
			},
			expected: testCategoryResult{
				Targets: map[string][]testResult{
					endpoint1: {
						{Name: "Ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
					},
					endpoint2: {
						{Name: "Ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
					},
				},
			},
			expectedErr: "",
		},
		{
			name: "write to file",
			config: testBeaconConfig{
				testConfig: testConfig{
					OutputJSON: "./write-to-file-test.json.tmp",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    time.Minute,
				},
				Endpoints: []string{endpoint1, endpoint2},
			},
			expected: testCategoryResult{
				Targets:      defaultFailingBNTests(t, endpoint1, endpoint2, port1, port2),
				Score:        categoryScoreC,
				CategoryName: beaconTestCategory,
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
			_, err := runTestBeacon(ctx, &buf, test.config)
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

func defaultFailingBNTests(_ *testing.T, endpoint1 string, endpoint2 string, port1 int, port2 int) map[string][]testResult {
	return map[string][]testResult{
		endpoint1: {
			{Name: "Ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
			{Name: "PingMeasure", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
			{Name: "Version", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
			{Name: "Synced", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
			{Name: "PeerCount", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port1))}},
			{Name: "PingLoad", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
			{Name: "Simulate1", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
			{Name: "Simulate10", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
			{Name: "Simulate100", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
			{Name: "Simulate500", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
			{Name: "Simulate1000", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
			{Name: "SimulateCustom", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
		},
		endpoint2: {
			{Name: "Ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
			{Name: "PingMeasure", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
			{Name: "Version", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
			{Name: "Synced", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
			{Name: "PeerCount", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: testResultError{errors.New(fmt.Sprintf(`%v: connect: connection refused`, port2))}},
			{Name: "PingLoad", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
			{Name: "Simulate1", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
			{Name: "Simulate10", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
			{Name: "Simulate100", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
			{Name: "Simulate500", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
			{Name: "Simulate1000", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
			{Name: "SimulateCustom", Verdict: testVerdictSkipped, Measurement: "", Suggestion: "", Error: testResultError{}},
		},
	}
}

func startHealthyMockedBeaconNode(t *testing.T) *httptest.Server {
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
		case "/eth/v1/node/version":
			_, err := w.Write([]byte(`{"data":{"version":"BeaconNodeProvider/v1.0.0/linux_x86_64"}}`))
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
			name:        "no output json on quiet",
			args:        []string{"beacon", "--endpoints=\"test.endpoint\"", "--quiet"},
			expectedErr: "on --quiet, an --output-json is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := newAlphaCmd(newTestBeaconCmd(func(context.Context, io.Writer, testBeaconConfig) (testCategoryResult, error) {
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
