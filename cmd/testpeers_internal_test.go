// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

//go:generate go test . -run=TestPeersTest -update

//nolint:dupl // code is marked as duplicate currently, as we are testing the same test skeleton, ignore for now
func TestPeersTest(t *testing.T) {
	tests := []struct {
		name        string
		config      testPeersConfig
		expected    testCategoryResult
		expectedErr string
		cleanup     func(*testing.T, string)
	}{
		{
			name: "default scenario",
			config: testPeersConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    time.Minute,
				},
				ENRs: []string{"enr:-1", "enr:-2", "enr:-3"},
			},
			expected: testCategoryResult{
				CategoryName: "peers",
				Targets: map[string][]testResult{
					"self": {
						{Name: "natOpen", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "natOpen not implemented"},
					},
					"enr:-1": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "ping not implemented"},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "10ms", Suggestion: "", Error: "pingMeasure not implemented"},
						{Name: "pingLoad", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "pingLoad not implemented"},
					},
					"enr:-2": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "ping not implemented"},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "10ms", Suggestion: "", Error: "pingMeasure not implemented"},
						{Name: "pingLoad", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "pingLoad not implemented"},
					},
					"enr:-3": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "ping not implemented"},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "10ms", Suggestion: "", Error: "pingMeasure not implemented"},
						{Name: "pingLoad", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "pingLoad not implemented"},
					},
				},
				Score: categoryScoreC,
			},
			expectedErr: "",
		},
		{
			name: "timeout",
			config: testPeersConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    100 * time.Millisecond,
				},
				ENRs: []string{"enr:-1", "enr:-2", "enr:-3"},
			},
			expected: testCategoryResult{
				CategoryName: "peers",
				Targets: map[string][]testResult{
					"self": {
						{Name: "natOpen", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "natOpen not implemented"},
					},
					"enr:-1": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "ping not implemented"},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "timeout"},
					},
					"enr:-2": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "ping not implemented"},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "timeout"},
					},
					"enr:-3": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "ping not implemented"},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "timeout"},
					},
				},
				Score: categoryScoreC,
			},
			expectedErr: "",
		},
		{
			name: "quiet",
			config: testPeersConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      true,
					TestCases:  nil,
					Timeout:    24 * time.Hour,
				},
				ENRs: []string{"enr:-1", "enr:-2", "enr:-3"},
			},
			expected: testCategoryResult{
				CategoryName: "peers",
				Targets: map[string][]testResult{
					"self": {
						{Name: "natOpen", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "natOpen not implemented"},
					},
					"enr:-1": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "ping not implemented"},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "10ms", Suggestion: "", Error: "pingMeasure not implemented"},
						{Name: "pingLoad", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "pingLoad not implemented"},
					},
					"enr:-2": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "ping not implemented"},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "10ms", Suggestion: "", Error: "pingMeasure not implemented"},
						{Name: "pingLoad", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "pingLoad not implemented"},
					},
					"enr:-3": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "ping not implemented"},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "10ms", Suggestion: "", Error: "pingMeasure not implemented"},
						{Name: "pingLoad", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "pingLoad not implemented"},
					},
				},
				Score: categoryScoreC,
			},
			expectedErr: "",
		},
		{
			name: "unsupported test",
			config: testPeersConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  []string{"notSupportedTest"},
					Timeout:    24 * time.Hour,
				},
				ENRs: []string{"enr:-1", "enr:-2", "enr:-3"},
			},
			expected:    testCategoryResult{},
			expectedErr: "test case not supported",
		},
		{
			name: "custom test cases",
			config: testPeersConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  []string{"ping"},
					Timeout:    24 * time.Hour,
				},
				ENRs: []string{"enr:-1", "enr:-2", "enr:-3"},
			},
			expected: testCategoryResult{
				CategoryName: "peers",
				Targets: map[string][]testResult{
					"enr:-1": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "ping not implemented"},
					},
					"enr:-2": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "ping not implemented"},
					},
					"enr:-3": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "ping not implemented"},
					},
				},
				Score: categoryScoreC,
			},
			expectedErr: "",
		},
		{
			name: "write to file",
			config: testPeersConfig{
				testConfig: testConfig{
					OutputToml: "./write-to-file-test.toml.tmp",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    time.Duration(rand.Int31n(222)) * time.Hour,
				},
				ENRs: []string{"enr:-1", "enr:-2", "enr:-3"},
			},
			expected: testCategoryResult{
				CategoryName: "peers",
				Targets: map[string][]testResult{
					"self": {
						{Name: "natOpen", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "natOpen not implemented"},
					},
					"enr:-1": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "ping not implemented"},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "10ms", Suggestion: "", Error: "pingMeasure not implemented"},
						{Name: "pingLoad", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "pingLoad not implemented"},
					},
					"enr:-2": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "ping not implemented"},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "10ms", Suggestion: "", Error: "pingMeasure not implemented"},
						{Name: "pingLoad", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "pingLoad not implemented"},
					},
					"enr:-3": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "ping not implemented"},
						{Name: "pingMeasure", Verdict: testVerdictFail, Measurement: "10ms", Suggestion: "", Error: "pingMeasure not implemented"},
						{Name: "pingLoad", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: "pingLoad not implemented"},
					},
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
			err := runTestPeers(ctx, &buf, test.config)
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

func TestPeersTestFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectedErr string
	}{
		{
			name:        "default scenario",
			args:        []string{"peers", "--enrs=\"test.endpoint\""},
			expectedErr: "",
		},
		{
			name:        "no enrs flag",
			args:        []string{"peers"},
			expectedErr: "required flag(s) \"enrs\" not set",
		},
		{
			name:        "no output toml on quiet",
			args:        []string{"peers", "--enrs=\"test.endpoint\"", "--quiet"},
			expectedErr: "on --quiet, an --output-toml is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := newAlphaCmd(newTestPeersCmd(func(context.Context, io.Writer, testPeersConfig) error { return nil }))
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

func testWriteOut(t *testing.T, expectedRes testCategoryResult, buf bytes.Buffer) {
	t.Helper()
	bufTests := strings.Split(buf.String(), "\n")
	bufTests = slices.Delete(bufTests, 0, 8)
	bufTests = slices.Delete(bufTests, len(bufTests)-4, len(bufTests))

	nTargets := len(maps.Keys(expectedRes.Targets))
	require.Len(t, bufTests, len(slices.Concat(maps.Values(expectedRes.Targets)...))+nTargets*2)

	for i := 0; i < nTargets; i++ {
		bufTests = bufTests[1:]
		target := strings.Trim(bufTests[0], " ")
		bufTests = bufTests[1:]
		for _, test := range expectedRes.Targets[target] {
			name, res, exist := strings.Cut(bufTests[0], " ")
			require.True(t, exist)
			require.Equal(t, name, test.Name)
			require.Contains(t, res, test.Verdict)
			require.Contains(t, res, test.Measurement)
			require.Contains(t, res, test.Suggestion)
			require.Contains(t, res, test.Error)
			bufTests = bufTests[1:]
		}
	}

	require.Empty(t, bufTests)
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
	require.Equal(t, len(expectedRes.Targets), len(res.Targets))
	for targetName, testResults := range res.Targets {
		for idx, testRes := range testResults {
			require.Equal(t, expectedRes.Targets[targetName][idx].Verdict, testRes.Verdict)
			require.Equal(t, expectedRes.Targets[targetName][idx].Verdict, testRes.Verdict)
			require.Equal(t, expectedRes.Targets[targetName][idx].Measurement, testRes.Measurement)
			require.Equal(t, expectedRes.Targets[targetName][idx].Suggestion, testRes.Suggestion)
			require.Equal(t, expectedRes.Targets[targetName][idx].Error, testRes.Error)
		}
	}
}
