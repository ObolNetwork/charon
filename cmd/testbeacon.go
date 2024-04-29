// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

type testBeaconConfig struct {
	testConfig
	Endpoints []string
}

const (
	thresholdBeaconPeersAvg = 20
	thresholdBeaconPeersBad = 5
)

func newTestBeaconCmd(runFunc func(context.Context, io.Writer, testBeaconConfig) error) *cobra.Command {
	var config testBeaconConfig

	cmd := &cobra.Command{
		Use:   "beacon",
		Short: "Run multiple tests towards beacon nodes",
		Long:  `Run multiple tests towards beacon nodes. Verify that Charon can efficiently interact with Beacon Node(s).`,
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return mustOutputToFileOnQuiet(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFunc(cmd.Context(), cmd.OutOrStdout(), config)
		},
	}

	bindTestFlags(cmd, &config.testConfig)
	bindTestBeaconFlags(cmd, &config)

	return cmd
}

func bindTestBeaconFlags(cmd *cobra.Command, config *testBeaconConfig) {
	const endpoints = "endpoints"
	cmd.Flags().StringSliceVar(&config.Endpoints, endpoints, nil, "[REQUIRED] Comma separated list of one or more beacon node endpoint URLs.")
	mustMarkFlagRequired(cmd, endpoints)
}

func supportedBeaconTestCases() map[testCaseName]func(context.Context, *testBeaconConfig, string) testResult {
	return map[testCaseName]func(context.Context, *testBeaconConfig, string) testResult{
		{name: "ping", order: 1}:        beaconPingTest,
		{name: "pingMeasure", order: 2}: beaconPingMeasureTest,
		{name: "isSynced", order: 3}:    beaconIsSyncedTest,
		{name: "peerCount", order: 4}:   beaconPeerCountTest,
	}
}

func runTestBeacon(ctx context.Context, w io.Writer, cfg testBeaconConfig) (err error) {
	testCases := supportedBeaconTestCases()
	queuedTests := filterTests(maps.Keys(testCases), cfg.testConfig)
	if len(queuedTests) == 0 {
		return errors.New("test case not supported")
	}
	sortTests(queuedTests)

	parentCtx := ctx
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	timeoutCtx, cancel := context.WithTimeout(parentCtx, cfg.Timeout)
	defer cancel()

	resultsCh := make(chan map[string][]testResult)
	testResults := make(map[string][]testResult)
	startTime := time.Now()

	// run test suite for all beacon nodes
	go testAllBeacons(timeoutCtx, queuedTests, testCases, cfg, resultsCh)

	for result := range resultsCh {
		maps.Copy(testResults, result)
	}

	execTime := Duration{time.Since(startTime)}

	// use highest score as score of all
	var score categoryScore
	for _, t := range testResults {
		targetScore := calculateScore(t)
		if score == "" || score > targetScore {
			score = targetScore
		}
	}

	res := testCategoryResult{
		CategoryName:  "beacon",
		Targets:       testResults,
		ExecutionTime: execTime,
		Score:         score,
	}

	if !cfg.Quiet {
		err = writeResultToWriter(res, w)
		if err != nil {
			return err
		}
	}

	if cfg.OutputToml != "" {
		err = writeResultToFile(res, cfg.OutputToml)
		if err != nil {
			return err
		}
	}

	return nil
}

func testAllBeacons(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]func(context.Context, *testBeaconConfig, string) testResult, cfg testBeaconConfig, resCh chan map[string][]testResult) {
	defer close(resCh)
	// run tests for all beacon nodes
	res := make(map[string][]testResult)
	chs := []chan map[string][]testResult{}
	for _, enr := range cfg.Endpoints {
		ch := make(chan map[string][]testResult)
		chs = append(chs, ch)
		go testSingleBeacon(ctx, queuedTestCases, allTestCases, cfg, enr, ch)
	}

	for _, ch := range chs {
		for {
			// we are checking for context done (timeout) inside the go routine
			result, ok := <-ch
			if !ok {
				break
			}
			maps.Copy(res, result)
		}
	}

	resCh <- res
}

func testSingleBeacon(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]func(context.Context, *testBeaconConfig, string) testResult, cfg testBeaconConfig, target string, resCh chan map[string][]testResult) {
	defer close(resCh)
	ch := make(chan testResult)
	res := []testResult{}
	// run all beacon tests for a beacon node, pushing each completed test to the channel until all are complete or timeout occurs
	go runBeaconTest(ctx, queuedTestCases, allTestCases, cfg, target, ch)

	testCounter := 0
	finished := false
	for !finished {
		var name string
		select {
		case <-ctx.Done():
			name = queuedTestCases[testCounter].name
			res = append(res, testResult{Name: name, Verdict: testVerdictFail, Error: errTimeoutInterrupted})
			finished = true
		case result, ok := <-ch:
			if !ok {
				finished = true
				break
			}
			name = queuedTestCases[testCounter].name
			testCounter++
			result.Name = name
			res = append(res, result)
		}
	}

	resCh <- map[string][]testResult{target: res}
}

func runBeaconTest(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]func(context.Context, *testBeaconConfig, string) testResult, cfg testBeaconConfig, target string, ch chan testResult) {
	defer close(ch)
	for _, t := range queuedTestCases {
		select {
		case <-ctx.Done():
			return
		default:
			ch <- allTestCases[t](ctx, &cfg, target)
		}
	}
}

func beaconPingTest(ctx context.Context, _ *testBeaconConfig, target string) testResult {
	testRes := testResult{Name: "Ping"}

	client := http.Client{}
	targetEndpoint := fmt.Sprintf("%v/eth/v1/node/health", target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetEndpoint, nil)
	if err != nil {
		testRes.Verdict = testVerdictFail
		testRes.Error = testResultError{err}

		return testRes
	}
	resp, err := client.Do(req)
	if err != nil {
		testRes.Verdict = testVerdictFail
		testRes.Error = testResultError{err}

		return testRes
	}
	defer resp.Body.Close()

	if resp.StatusCode > 399 {
		testRes.Verdict = testVerdictFail
		testRes.Error = testResultError{errors.New("status code %v", z.Int("status_code", resp.StatusCode))}

		return testRes
	}

	testRes.Verdict = testVerdictOk

	return testRes
}

func beaconPingMeasureTest(ctx context.Context, _ *testBeaconConfig, target string) testResult {
	testRes := testResult{Name: "PingMeasure"}

	var start time.Time
	var firstByte time.Duration

	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			firstByte = time.Since(start)
		},
	}

	start = time.Now()
	targetEndpoint := fmt.Sprintf("%v/eth/v1/node/health", target)
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, targetEndpoint, nil)
	if err != nil {
		testRes.Verdict = testVerdictFail
		testRes.Error = testResultError{err}

		return testRes
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		testRes.Verdict = testVerdictFail
		testRes.Error = testResultError{err}

		return testRes
	}
	defer resp.Body.Close()

	if resp.StatusCode > 399 {
		testRes.Verdict = testVerdictFail
		testRes.Error = testResultError{errors.New("status code %v", z.Int("status_code", resp.StatusCode))}

		return testRes
	}

	if firstByte > thresholdMeasureBad {
		testRes.Verdict = testVerdictBad
	} else if firstByte > thresholdMeasureAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = Duration{firstByte}.String()

	return testRes
}

func beaconIsSyncedTest(ctx context.Context, _ *testBeaconConfig, target string) testResult {
	testRes := testResult{Name: "isSynced"}

	type isSyncedResponseData struct {
		HeadSlot     string `json:"head_slot"`
		SyncDistance string `json:"sync_distance"`
		IsSyncing    bool   `json:"is_syncing"`
		IsOptimistic bool   `json:"is_optimistic"`
		ElOffline    bool   `json:"el_offline"`
	}

	type isSyncedResponse struct {
		Data isSyncedResponseData `json:"data"`
	}

	client := http.Client{}
	targetEndpoint := fmt.Sprintf("%v/eth/v1/node/syncing", target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetEndpoint, nil)
	if err != nil {
		testRes.Verdict = testVerdictFail
		testRes.Error = testResultError{err}

		return testRes
	}
	resp, err := client.Do(req)
	if err != nil {
		testRes.Verdict = testVerdictFail
		testRes.Error = testResultError{err}

		return testRes
	}

	if resp.StatusCode > 399 {
		testRes.Verdict = testVerdictFail
		testRes.Error = testResultError{errors.New("status code %v", z.Int("status_code", resp.StatusCode))}

		return testRes
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		testRes.Verdict = testVerdictFail
		testRes.Error = testResultError{err}

		return testRes
	}
	defer resp.Body.Close()

	var respUnmarshaled isSyncedResponse
	err = json.Unmarshal(b, &respUnmarshaled)
	if err != nil {
		testRes.Verdict = testVerdictFail
		testRes.Error = testResultError{err}

		return testRes
	}

	if respUnmarshaled.Data.IsSyncing {
		testRes.Verdict = testVerdictFail

		return testRes
	}

	testRes.Verdict = testVerdictOk

	return testRes
}

func beaconPeerCountTest(ctx context.Context, _ *testBeaconConfig, target string) testResult {
	testRes := testResult{Name: "peerCount"}

	type peerCountResponseMeta struct {
		Count int `json:"count"`
	}

	type peerCountResponse struct {
		Meta peerCountResponseMeta `json:"meta"`
	}

	client := http.Client{}
	targetEndpoint := fmt.Sprintf("%v/eth/v1/node/peers?state=connected", target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetEndpoint, nil)
	if err != nil {
		testRes.Verdict = testVerdictFail
		testRes.Error = testResultError{err}

		return testRes
	}
	resp, err := client.Do(req)
	if err != nil {
		testRes.Verdict = testVerdictFail
		testRes.Error = testResultError{err}

		return testRes
	}

	if resp.StatusCode > 399 {
		testRes.Verdict = testVerdictFail
		testRes.Error = testResultError{errors.New("status code %v", z.Int("status_code", resp.StatusCode))}

		return testRes
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		testRes.Verdict = testVerdictFail
		testRes.Error = testResultError{err}

		return testRes
	}
	defer resp.Body.Close()

	var respUnmarshaled peerCountResponse
	err = json.Unmarshal(b, &respUnmarshaled)
	if err != nil {
		testRes.Verdict = testVerdictFail
		testRes.Error = testResultError{err}

		return testRes
	}

	testRes.Measurement = strconv.Itoa(respUnmarshaled.Meta.Count)

	if respUnmarshaled.Meta.Count < thresholdBeaconPeersBad {
		testRes.Verdict = testVerdictBad
	} else if respUnmarshaled.Meta.Count < thresholdBeaconPeersAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}

	return testRes
}
