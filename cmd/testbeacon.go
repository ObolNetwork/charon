// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"sync"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

type testBeaconConfig struct {
	testConfig
	Endpoints        []string
	EnableLoadTest   bool
	LoadTestDuration time.Duration
}

type testCaseBeacon func(context.Context, *testBeaconConfig, string) testResult

const (
	thresholdBeaconMeasureAvg  = 40 * time.Millisecond
	thresholdBeaconMeasurePoor = 100 * time.Millisecond
	thresholdBeaconLoadAvg     = 40 * time.Millisecond
	thresholdBeaconLoadPoor    = 100 * time.Millisecond
	thresholdBeaconPeersAvg    = 50
	thresholdBeaconPeersPoor   = 20
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
	cmd.Flags().BoolVar(&config.EnableLoadTest, "enable-load-test", false, "Enable load test, not advisable when testing towards external beacon nodes.")
	cmd.Flags().DurationVar(&config.LoadTestDuration, "load-test-duration", 5*time.Second, "Time to keep running the load tests in seconds. For each second a new continuous ping instance is spawned.")
}

func supportedBeaconTestCases() map[testCaseName]testCaseBeacon {
	return map[testCaseName]testCaseBeacon{
		{name: "ping", order: 1}:        beaconPingTest,
		{name: "pingMeasure", order: 2}: beaconPingMeasureTest,
		{name: "isSynced", order: 3}:    beaconIsSyncedTest,
		{name: "peerCount", order: 4}:   beaconPeerCountTest,
		{name: "pingLoad", order: 5}:    beaconPingLoadTest,
	}
}

func runTestBeacon(ctx context.Context, w io.Writer, cfg testBeaconConfig) (err error) {
	testCases := supportedBeaconTestCases()
	queuedTests := filterTests(maps.Keys(testCases), cfg.testConfig)
	if len(queuedTests) == 0 {
		return errors.New("test case not supported")
	}
	sortTests(queuedTests)

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
		CategoryName:  beaconTestCategory,
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

func beaconPingOnce(ctx context.Context, target string) (time.Duration, error) {
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
		return 0, errors.Wrap(err, "create new request with trace and context")
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode > 399 {
		return 0, errors.New("status code %v", z.Int("status_code", resp.StatusCode))
	}

	return firstByte, nil
}

func beaconPingMeasureTest(ctx context.Context, _ *testBeaconConfig, target string) testResult {
	testRes := testResult{Name: "PingMeasure"}

	rtt, err := beaconPingOnce(ctx, target)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	if rtt > thresholdBeaconMeasurePoor {
		testRes.Verdict = testVerdictPoor
	} else if rtt > thresholdBeaconMeasureAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = Duration{rtt}.String()

	return testRes
}

func pingBeaconContinuously(ctx context.Context, target string, resCh chan<- time.Duration) {
	for {
		rtt, err := beaconPingOnce(ctx, target)
		if err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case resCh <- rtt:
			awaitTime := rand.Intn(100) //nolint:gosec // weak generator is not an issue here
			sleepWithContext(ctx, time.Duration(awaitTime)*time.Millisecond)
		}
	}
}

func beaconPingLoadTest(ctx context.Context, conf *testBeaconConfig, target string) testResult {
	testRes := testResult{Name: "BeaconLoad"}
	if !conf.EnableLoadTest {
		testRes.Verdict = testVerdictSkipped
		return testRes
	}
	log.Info(ctx, "Running ping load tests...",
		z.Any("duration", conf.LoadTestDuration),
		z.Any("target", target),
	)

	testResCh := make(chan time.Duration, math.MaxInt16)
	pingCtx, cancel := context.WithTimeout(ctx, conf.LoadTestDuration)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var wg sync.WaitGroup
	for pingCtx.Err() == nil {
		select {
		case <-ticker.C:
			wg.Add(1)
			go func() {
				pingBeaconContinuously(pingCtx, target, testResCh)
				wg.Done()
			}()
		case <-pingCtx.Done():
		}
	}
	wg.Wait()
	close(testResCh)
	log.Info(ctx, "Ping load tests finished", z.Any("target", target))

	highestRTT := time.Duration(0)
	for rtt := range testResCh {
		if rtt > highestRTT {
			highestRTT = rtt
		}
	}
	if highestRTT > thresholdBeaconLoadPoor {
		testRes.Verdict = testVerdictPoor
	} else if highestRTT > thresholdBeaconLoadAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = Duration{highestRTT}.String()

	return testRes
}

func beaconIsSyncedTest(ctx context.Context, _ *testBeaconConfig, target string) testResult {
	testRes := testResult{Name: "isSynced"}

	type isSyncedResponse struct {
		Data eth2v1.SyncState `json:"data"`
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

	if respUnmarshaled.Meta.Count < thresholdBeaconPeersPoor {
		testRes.Verdict = testVerdictPoor
	} else if respUnmarshaled.Meta.Count < thresholdBeaconPeersAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}

	return testRes
}
