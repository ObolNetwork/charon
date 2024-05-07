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
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

type testBeaconConfig struct {
	testConfig
	Endpoints []string
}

type testCaseBeacon func(context.Context, *testBeaconConfig, string) testResult

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

func supportedBeaconTestCases() map[testCaseName]testCaseBeacon {
	return map[testCaseName]testCaseBeacon{
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

	if ctx == nil {
		ctx = context.Background()
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	testResultsChan := make(chan map[string][]testResult)
	testResults := make(map[string][]testResult)
	startTime := time.Now()

	// run test suite for all beacon nodes
	go testAllBeacons(timeoutCtx, queuedTests, testCases, cfg, testResultsChan)

	for result := range testResultsChan {
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

func testAllBeacons(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]testCaseBeacon, conf testBeaconConfig, allBeaconsResCh chan map[string][]testResult) {
	defer close(allBeaconsResCh)
	// run tests for all beacon nodes
	allBeaconsRes := make(map[string][]testResult)
	singleBeaconResCh := make(chan map[string][]testResult)
	group, _ := errgroup.WithContext(ctx)

	for _, endpoint := range conf.Endpoints {
		currEndpoint := endpoint // TODO: can be removed after go1.22 version bump
		group.Go(func() error {
			return testSingleBeacon(ctx, queuedTestCases, allTestCases, conf, currEndpoint, singleBeaconResCh)
		})
	}

	doneReading := make(chan bool)
	go func() {
		for singlePeerRes := range singleBeaconResCh {
			maps.Copy(allBeaconsRes, singlePeerRes)
		}
		doneReading <- true
	}()

	err := group.Wait()
	if err != nil {
		return
	}
	close(singleBeaconResCh)
	<-doneReading

	allBeaconsResCh <- allBeaconsRes
}

func testSingleBeacon(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]testCaseBeacon, cfg testBeaconConfig, target string, resCh chan map[string][]testResult) error {
	singleTestResCh := make(chan testResult)
	allTestRes := []testResult{}

	// run all beacon tests for a beacon node, pushing each completed test to the channel until all are complete or timeout occurs
	go runBeaconTest(ctx, queuedTestCases, allTestCases, cfg, target, singleTestResCh)
	testCounter := 0
	finished := false
	for !finished {
		var testName string
		select {
		case <-ctx.Done():
			testName = queuedTestCases[testCounter].name
			allTestRes = append(allTestRes, testResult{Name: testName, Verdict: testVerdictFail, Error: errTimeoutInterrupted})
			finished = true
		case result, ok := <-singleTestResCh:
			if !ok {
				finished = true
				break
			}
			testName = queuedTestCases[testCounter].name
			testCounter++
			result.Name = testName
			allTestRes = append(allTestRes, result)
		}
	}

	resCh <- map[string][]testResult{target: allTestRes}

	return nil
}

func runBeaconTest(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]testCaseBeacon, cfg testBeaconConfig, target string, ch chan testResult) {
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
		return failedTestResult(testRes, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return failedTestResult(testRes, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode > 399 {
		return failedTestResult(testRes, errors.New("status code %v", z.Int("status_code", resp.StatusCode)))
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
		return failedTestResult(testRes, err)
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return failedTestResult(testRes, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode > 399 {
		return failedTestResult(testRes, errors.New("status code %v", z.Int("status_code", resp.StatusCode)))
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
		return failedTestResult(testRes, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	if resp.StatusCode > 399 {
		return failedTestResult(testRes, errors.New("status code %v", z.Int("status_code", resp.StatusCode)))
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return failedTestResult(testRes, err)
	}
	defer resp.Body.Close()

	var respUnmarshaled isSyncedResponse
	err = json.Unmarshal(b, &respUnmarshaled)
	if err != nil {
		return failedTestResult(testRes, err)
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
		return failedTestResult(testRes, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	if resp.StatusCode > 399 {
		return failedTestResult(testRes, errors.New("status code %v", z.Int("status_code", resp.StatusCode)))
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return failedTestResult(testRes, err)
	}
	defer resp.Body.Close()

	var respUnmarshaled peerCountResponse
	err = json.Unmarshal(b, &respUnmarshaled)
	if err != nil {
		return failedTestResult(testRes, err)
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
