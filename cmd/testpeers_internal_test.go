// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cmd/relay"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -run=TestPeersTest -update

//nolint:dupl // code is marked as duplicate currently, as we are testing the same test skeleton, ignore for now
func TestPeersTest(t *testing.T) {
	peer1PrivKey := base64ToPrivKey(t, "GCc1IKup3kKVxSd9iSu8iX5hc37coxAXasYpGFd/cwo=")
	peer2PrivKey := base64ToPrivKey(t, "9PhpdrWEDJugHgoXhpbk2KqR4Gj5QZP/YNxNeJ3Q2+A=")
	peer3PrivKey := base64ToPrivKey(t, "GpicOFPB/c/ZKIy1/fOt/4BmEekhFuyxa/SGcjrNe9o=")
	freeTCPAddr := testutil.AvailableAddr(t)

	tests := []struct {
		name        string
		config      testPeersConfig
		expected    testCategoryResult
		expectedErr string
		prepare     func(*testing.T, testPeersConfig) testPeersConfig
		cleanup     func(*testing.T, string)
	}{
		{
			name: "default scenario",
			config: testPeersConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      false,
					TestCases:  nil,
					Timeout:    10 * time.Second,
				},
				ENRs: []string{
					"enr:-HW4QBHlcyD3fYWUMADiOv4OxODaL5wJG0a7P7d_ltu4VZe1MibZ1N-twFaoaq0BoCtXcY71etxLJGeEZT5p3XCO6GOAgmlkgnY0iXNlY3AyNTZrMaEDI2HRUlVBag__njkOWEEQRLlC9ylIVCrIXOuNBSlrx6o",
					"enr:-HW4QDwUF804f4WhUjwcp4JJ-PrRH0glQZv8s2cVHlBRPJ3SYcYO-dvJGsKhztffrski5eujJkl8oAc983MZy6-PqF2AgmlkgnY0iXNlY3AyNTZrMaECPEPryjkmUBnQFyjmMw9rl7DVtKL0243nN5iepqsvKDw",
					"enr:-HW4QPSBgUTag8oZs3zIsgWzlBUrSgT8pgZmFJa7HWwKXUcRLlISa68OJtp-JTzhUXsJ2vSGwKGACn0OTatWdJATxn-AgmlkgnY0iXNlY3AyNTZrMaECA3R_ffXLXCLJsfEwf6xeoAFgWnDIOdq8kS0Yqkhwbr0",
				},
				Log:                     log.DefaultConfig(),
				LoadTestDuration:        2 * time.Second,
				DirectConnectionTimeout: time.Second,
				P2P: p2p.Config{
					TCPAddrs: []string{freeTCPAddr.String()},
				},
			},
			expected: testCategoryResult{
				CategoryName: "peers",
				Targets: map[string][]testResult{
					"self": {
						{Name: "libp2pTCPPortOpenTest", Verdict: testVerdictOk, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
					"inexpensive-farm - enr:-HW4QBHlcyD3fYWUMADiOv4OxODaL5wJG0a7P7d_ltu4VZe1MibZ1N-twFaoaq0BoCtXcY71etxLJGeEZT5p3XCO6GOAgmlkgnY0iXNlY3AyNTZrMaEDI2HRUlVBag__njkOWEEQRLlC9ylIVCrIXOuNBSlrx6o": {
						{Name: "ping", Verdict: testVerdictOk, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "pingMeasure", Verdict: testVerdictGood, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "pingLoad", Verdict: testVerdictGood, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "directConn", Verdict: testVerdictOk, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
					"anxious-pencil - enr:-HW4QDwUF804f4WhUjwcp4JJ-PrRH0glQZv8s2cVHlBRPJ3SYcYO-dvJGsKhztffrski5eujJkl8oAc983MZy6-PqF2AgmlkgnY0iXNlY3AyNTZrMaECPEPryjkmUBnQFyjmMw9rl7DVtKL0243nN5iepqsvKDw": {
						{Name: "ping", Verdict: testVerdictOk, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "pingMeasure", Verdict: testVerdictGood, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "pingLoad", Verdict: testVerdictGood, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "directConn", Verdict: testVerdictOk, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
					"important-pen - enr:-HW4QPSBgUTag8oZs3zIsgWzlBUrSgT8pgZmFJa7HWwKXUcRLlISa68OJtp-JTzhUXsJ2vSGwKGACn0OTatWdJATxn-AgmlkgnY0iXNlY3AyNTZrMaECA3R_ffXLXCLJsfEwf6xeoAFgWnDIOdq8kS0Yqkhwbr0": {
						{Name: "ping", Verdict: testVerdictOk, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "pingMeasure", Verdict: testVerdictGood, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "pingLoad", Verdict: testVerdictGood, Measurement: "", Suggestion: "", Error: testResultError{}},
						{Name: "directConn", Verdict: testVerdictOk, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
				},
				Score: categoryScoreC,
			},
			expectedErr: "",
			prepare: func(t *testing.T, conf testPeersConfig) testPeersConfig {
				t.Helper()
				ctx := context.Background()
				newConfig := conf

				// start local relay, so direct connection can be established
				relayAddr := startRelay(ctx, t)
				newConfig.P2P.Relays = []string{relayAddr}
				freeTCPAddr := testutil.AvailableAddr(t)
				newConfig.P2P.TCPAddrs = []string{fmt.Sprintf("127.0.0.1:%v", freeTCPAddr.Port)}

				// start peers
				enr1 := startPeer(t, newConfig, &peer1PrivKey)
				enr2 := startPeer(t, newConfig, &peer2PrivKey)
				enr3 := startPeer(t, newConfig, &peer3PrivKey)
				newConfig.ENRs = []string{enr1.String(), enr2.String(), enr3.String()}

				return newConfig
			},
		},
		{
			name: "quiet",
			config: testPeersConfig{
				testConfig: testConfig{
					OutputToml: "",
					Quiet:      true,
					TestCases:  nil,
					Timeout:    200 * time.Millisecond,
				},
				ENRs: []string{
					"enr:-HW4QBHlcyD3fYWUMADiOv4OxODaL5wJG0a7P7d_ltu4VZe1MibZ1N-twFaoaq0BoCtXcY71etxLJGeEZT5p3XCO6GOAgmlkgnY0iXNlY3AyNTZrMaEDI2HRUlVBag__njkOWEEQRLlC9ylIVCrIXOuNBSlrx6o",
					"enr:-HW4QDwUF804f4WhUjwcp4JJ-PrRH0glQZv8s2cVHlBRPJ3SYcYO-dvJGsKhztffrski5eujJkl8oAc983MZy6-PqF2AgmlkgnY0iXNlY3AyNTZrMaECPEPryjkmUBnQFyjmMw9rl7DVtKL0243nN5iepqsvKDw",
					"enr:-HW4QPSBgUTag8oZs3zIsgWzlBUrSgT8pgZmFJa7HWwKXUcRLlISa68OJtp-JTzhUXsJ2vSGwKGACn0OTatWdJATxn-AgmlkgnY0iXNlY3AyNTZrMaECA3R_ffXLXCLJsfEwf6xeoAFgWnDIOdq8kS0Yqkhwbr0",
				},
				Log: log.DefaultConfig(),
			},
			expected: testCategoryResult{
				CategoryName: "peers",
				Targets: map[string][]testResult{
					"self": {
						{Name: "libp2pTCPPortOpenTest", Verdict: testVerdictOk, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
					"inexpensive-farm - enr:-HW4QBHlcyD3fYWUMADiOv4OxODaL5wJG0a7P7d_ltu4VZe1MibZ1N-twFaoaq0BoCtXcY71etxLJGeEZT5p3XCO6GOAgmlkgnY0iXNlY3AyNTZrMaEDI2HRUlVBag__njkOWEEQRLlC9ylIVCrIXOuNBSlrx6o": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errTimeoutInterrupted},
					},
					"anxious-pencil - enr:-HW4QDwUF804f4WhUjwcp4JJ-PrRH0glQZv8s2cVHlBRPJ3SYcYO-dvJGsKhztffrski5eujJkl8oAc983MZy6-PqF2AgmlkgnY0iXNlY3AyNTZrMaECPEPryjkmUBnQFyjmMw9rl7DVtKL0243nN5iepqsvKDw": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errTimeoutInterrupted},
					},
					"important-pen - enr:-HW4QPSBgUTag8oZs3zIsgWzlBUrSgT8pgZmFJa7HWwKXUcRLlISa68OJtp-JTzhUXsJ2vSGwKGACn0OTatWdJATxn-AgmlkgnY0iXNlY3AyNTZrMaECA3R_ffXLXCLJsfEwf6xeoAFgWnDIOdq8kS0Yqkhwbr0": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errTimeoutInterrupted},
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
					Timeout:    200 * time.Millisecond,
				},
				ENRs: []string{
					"enr:-HW4QBHlcyD3fYWUMADiOv4OxODaL5wJG0a7P7d_ltu4VZe1MibZ1N-twFaoaq0BoCtXcY71etxLJGeEZT5p3XCO6GOAgmlkgnY0iXNlY3AyNTZrMaEDI2HRUlVBag__njkOWEEQRLlC9ylIVCrIXOuNBSlrx6o",
					"enr:-HW4QDwUF804f4WhUjwcp4JJ-PrRH0glQZv8s2cVHlBRPJ3SYcYO-dvJGsKhztffrski5eujJkl8oAc983MZy6-PqF2AgmlkgnY0iXNlY3AyNTZrMaECPEPryjkmUBnQFyjmMw9rl7DVtKL0243nN5iepqsvKDw",
					"enr:-HW4QPSBgUTag8oZs3zIsgWzlBUrSgT8pgZmFJa7HWwKXUcRLlISa68OJtp-JTzhUXsJ2vSGwKGACn0OTatWdJATxn-AgmlkgnY0iXNlY3AyNTZrMaECA3R_ffXLXCLJsfEwf6xeoAFgWnDIOdq8kS0Yqkhwbr0",
				},
				Log: log.DefaultConfig(),
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
					Timeout:    200 * time.Millisecond,
				},
				ENRs: []string{
					"enr:-HW4QBHlcyD3fYWUMADiOv4OxODaL5wJG0a7P7d_ltu4VZe1MibZ1N-twFaoaq0BoCtXcY71etxLJGeEZT5p3XCO6GOAgmlkgnY0iXNlY3AyNTZrMaEDI2HRUlVBag__njkOWEEQRLlC9ylIVCrIXOuNBSlrx6o",
					"enr:-HW4QDwUF804f4WhUjwcp4JJ-PrRH0glQZv8s2cVHlBRPJ3SYcYO-dvJGsKhztffrski5eujJkl8oAc983MZy6-PqF2AgmlkgnY0iXNlY3AyNTZrMaECPEPryjkmUBnQFyjmMw9rl7DVtKL0243nN5iepqsvKDw",
					"enr:-HW4QPSBgUTag8oZs3zIsgWzlBUrSgT8pgZmFJa7HWwKXUcRLlISa68OJtp-JTzhUXsJ2vSGwKGACn0OTatWdJATxn-AgmlkgnY0iXNlY3AyNTZrMaECA3R_ffXLXCLJsfEwf6xeoAFgWnDIOdq8kS0Yqkhwbr0",
				},
				Log: log.DefaultConfig(),
			},
			expected: testCategoryResult{
				CategoryName: "peers",
				Targets: map[string][]testResult{
					"inexpensive-farm - enr:-HW4QBHlcyD3fYWUMADiOv4OxODaL5wJG0a7P7d_ltu4VZe1MibZ1N-twFaoaq0BoCtXcY71etxLJGeEZT5p3XCO6GOAgmlkgnY0iXNlY3AyNTZrMaEDI2HRUlVBag__njkOWEEQRLlC9ylIVCrIXOuNBSlrx6o": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errTimeoutInterrupted},
					},
					"anxious-pencil - enr:-HW4QDwUF804f4WhUjwcp4JJ-PrRH0glQZv8s2cVHlBRPJ3SYcYO-dvJGsKhztffrski5eujJkl8oAc983MZy6-PqF2AgmlkgnY0iXNlY3AyNTZrMaECPEPryjkmUBnQFyjmMw9rl7DVtKL0243nN5iepqsvKDw": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errTimeoutInterrupted},
					},
					"important-pen - enr:-HW4QPSBgUTag8oZs3zIsgWzlBUrSgT8pgZmFJa7HWwKXUcRLlISa68OJtp-JTzhUXsJ2vSGwKGACn0OTatWdJATxn-AgmlkgnY0iXNlY3AyNTZrMaECA3R_ffXLXCLJsfEwf6xeoAFgWnDIOdq8kS0Yqkhwbr0": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errTimeoutInterrupted},
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
					Timeout:    200 * time.Millisecond,
				},
				ENRs: []string{
					"enr:-HW4QBHlcyD3fYWUMADiOv4OxODaL5wJG0a7P7d_ltu4VZe1MibZ1N-twFaoaq0BoCtXcY71etxLJGeEZT5p3XCO6GOAgmlkgnY0iXNlY3AyNTZrMaEDI2HRUlVBag__njkOWEEQRLlC9ylIVCrIXOuNBSlrx6o",
					"enr:-HW4QDwUF804f4WhUjwcp4JJ-PrRH0glQZv8s2cVHlBRPJ3SYcYO-dvJGsKhztffrski5eujJkl8oAc983MZy6-PqF2AgmlkgnY0iXNlY3AyNTZrMaECPEPryjkmUBnQFyjmMw9rl7DVtKL0243nN5iepqsvKDw",
					"enr:-HW4QPSBgUTag8oZs3zIsgWzlBUrSgT8pgZmFJa7HWwKXUcRLlISa68OJtp-JTzhUXsJ2vSGwKGACn0OTatWdJATxn-AgmlkgnY0iXNlY3AyNTZrMaECA3R_ffXLXCLJsfEwf6xeoAFgWnDIOdq8kS0Yqkhwbr0",
				},
				Log: log.DefaultConfig(),
			},
			expected: testCategoryResult{
				CategoryName: "peers",
				Targets: map[string][]testResult{
					"self": {
						{Name: "libp2pTCPPortOpenTest", Verdict: testVerdictOk, Measurement: "", Suggestion: "", Error: testResultError{}},
					},
					"inexpensive-farm - enr:-HW4QBHlcyD3fYWUMADiOv4OxODaL5wJG0a7P7d_ltu4VZe1MibZ1N-twFaoaq0BoCtXcY71etxLJGeEZT5p3XCO6GOAgmlkgnY0iXNlY3AyNTZrMaEDI2HRUlVBag__njkOWEEQRLlC9ylIVCrIXOuNBSlrx6o": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errTimeoutInterrupted},
					},
					"anxious-pencil - enr:-HW4QDwUF804f4WhUjwcp4JJ-PrRH0glQZv8s2cVHlBRPJ3SYcYO-dvJGsKhztffrski5eujJkl8oAc983MZy6-PqF2AgmlkgnY0iXNlY3AyNTZrMaECPEPryjkmUBnQFyjmMw9rl7DVtKL0243nN5iepqsvKDw": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errTimeoutInterrupted},
					},
					"important-pen - enr:-HW4QPSBgUTag8oZs3zIsgWzlBUrSgT8pgZmFJa7HWwKXUcRLlISa68OJtp-JTzhUXsJ2vSGwKGACn0OTatWdJATxn-AgmlkgnY0iXNlY3AyNTZrMaECA3R_ffXLXCLJsfEwf6xeoAFgWnDIOdq8kS0Yqkhwbr0": {
						{Name: "ping", Verdict: testVerdictFail, Measurement: "", Suggestion: "", Error: errTimeoutInterrupted},
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
			ctx := context.Background()
			conf := test.config
			temp := t.TempDir()
			_, err := p2p.NewSavedPrivKey(temp)
			require.NoError(t, err)
			conf.DataDir = temp
			if test.prepare != nil {
				conf = test.prepare(t, conf)
			}

			var buf bytes.Buffer
			err = runTestPeers(ctx, &buf, conf)
			if test.expectedErr != "" {
				require.ErrorContains(t, err, test.expectedErr)
				return
			} else {
				require.NoError(t, err)
			}
			defer func() {
				if test.cleanup != nil {
					test.cleanup(t, conf.OutputToml)
				}
			}()

			if conf.Quiet {
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
			if test.Error.error != nil {
				require.Contains(t, res, test.Error.Error())
			}
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
			if expectedRes.Targets[targetName][idx].Error.error != nil {
				require.ErrorContains(t, testRes.Error.error, expectedRes.Targets[targetName][idx].Error.error.Error())
			}
		}
	}
}

func startPeer(t *testing.T, conf testPeersConfig, peerPrivKey *k1.PrivateKey) enr.Record {
	t.Helper()
	ctx := context.Background()
	peerConf := conf
	freeTCPAddr := testutil.AvailableAddr(t)
	peerConf.P2P.TCPAddrs = []string{fmt.Sprintf("127.0.0.1:%v", freeTCPAddr.Port)}

	relays, err := p2p.NewRelays(ctx, peerConf.P2P.Relays, "test")
	require.NoError(t, err)

	hostPrivKey, err := p2p.LoadPrivKey(peerConf.DataDir)
	require.NoError(t, err)
	hostENR, err := enr.New(hostPrivKey)
	require.NoError(t, err)
	hostAsPeer, err := p2p.NewPeerFromENR(hostENR, 1)
	require.NoError(t, err)

	connGater, err := p2p.NewConnGater([]peer.ID{hostAsPeer.ID}, relays)
	require.NoError(t, err)

	peerTCPNode, err := p2p.NewTCPNode(ctx, peerConf.P2P, peerPrivKey, connGater, false)
	require.NoError(t, err)

	for _, relay := range relays {
		relay := relay
		go p2p.NewRelayReserver(peerTCPNode, relay)(ctx)
	}

	go p2p.NewRelayRouter(peerTCPNode, []peer.ID{hostAsPeer.ID}, relays)(ctx)

	peerENR, err := enr.New(peerPrivKey)
	require.NoError(t, err)

	return peerENR
}

func base64ToPrivKey(t *testing.T, base64Key string) k1.PrivateKey {
	t.Helper()
	peer1PrivKeyBytes, err := base64.StdEncoding.DecodeString(base64Key)
	require.NoError(t, err)

	return *k1.PrivKeyFromBytes(peer1PrivKeyBytes)
}

func startRelay(parentCtx context.Context, t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	addr := testutil.AvailableAddr(t).String()

	errChan := make(chan error, 1)
	go func() {
		err := relay.Run(parentCtx, relay.Config{
			DataDir:  dir,
			HTTPAddr: addr,
			P2PConfig: p2p.Config{
				TCPAddrs: []string{testutil.AvailableAddr(t).String()},
			},
			LogConfig:     log.DefaultConfig(),
			AutoP2PKey:    true,
			MaxResPerPeer: 8,
			MaxConns:      1024,
		})
		t.Logf("Relay stopped: err=%v", err)
		errChan <- err
	}()

	endpoint := "http://" + addr

	// Wait up to 5s for bootnode to become available.
	ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
	defer cancel()

	isUp := make(chan struct{})
	go func() {
		for ctx.Err() == nil {
			_, err := http.Get(endpoint)
			if err != nil {
				time.Sleep(time.Millisecond * 100)
				continue
			}
			close(isUp)

			return
		}
	}()

	for {
		select {
		case <-ctx.Done():
			require.Fail(t, "Relay context canceled before startup")
			return ""
		case err := <-errChan:
			testutil.SkipIfBindErr(t, err)
			require.Fail(t, "Relay exitted before startup", "err=%v", err)

			return ""
		case <-isUp:
			return endpoint
		}
	}
}
