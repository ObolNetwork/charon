// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/errors"
)

type testMEVConfig struct {
	testConfig
	Endpoints []string
}

type testCaseMEV func(context.Context, *testMEVConfig, string) testResult

const (
	thresholdMEVMeasureAvg  = 40 * time.Millisecond
	thresholdMEVMeasurePoor = 100 * time.Millisecond
)

func newTestMEVCmd(runFunc func(context.Context, io.Writer, testMEVConfig) error) *cobra.Command {
	var config testMEVConfig

	cmd := &cobra.Command{
		Use:   "mev",
		Short: "Run multiple tests towards mev nodes",
		Long:  `Run multiple tests towards mev nodes. Verify that Charon can efficiently interact with MEV Node(s).`,
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return mustOutputToFileOnQuiet(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFunc(cmd.Context(), cmd.OutOrStdout(), config)
		},
	}

	bindTestFlags(cmd, &config.testConfig)
	bindTestMEVFlags(cmd, &config)

	return cmd
}

func bindTestMEVFlags(cmd *cobra.Command, config *testMEVConfig) {
	const endpoints = "endpoints"
	cmd.Flags().StringSliceVar(&config.Endpoints, endpoints, nil, "[REQUIRED] Comma separated list of one or more MEV relay endpoint URLs.")
	mustMarkFlagRequired(cmd, endpoints)
}

func supportedMEVTestCases() map[testCaseName]testCaseMEV {
	return map[testCaseName]testCaseMEV{
		{name: "ping", order: 1}:        mevPingTest,
		{name: "pingMeasure", order: 2}: mevPingMeasureTest,
	}
}

func runTestMEV(ctx context.Context, w io.Writer, cfg testMEVConfig) (err error) {
	testCases := supportedMEVTestCases()
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

	// run test suite for all mev nodes
	go testAllMEVs(timeoutCtx, queuedTests, testCases, cfg, testResultsChan)

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
		CategoryName:  mevTestCategory,
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

func testAllMEVs(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]testCaseMEV, conf testMEVConfig, allMEVsResCh chan map[string][]testResult) {
	defer close(allMEVsResCh)
	// run tests for all mev nodes
	allMEVsRes := make(map[string][]testResult)
	singleMEVResCh := make(chan map[string][]testResult)
	group, _ := errgroup.WithContext(ctx)

	for _, endpoint := range conf.Endpoints {
		group.Go(func() error {
			return testSingleMEV(ctx, queuedTestCases, allTestCases, conf, endpoint, singleMEVResCh)
		})
	}

	doneReading := make(chan bool)
	go func() {
		for singleMEVRes := range singleMEVResCh {
			maps.Copy(allMEVsRes, singleMEVRes)
		}
		doneReading <- true
	}()

	err := group.Wait()
	if err != nil {
		return
	}
	close(singleMEVResCh)
	<-doneReading

	allMEVsResCh <- allMEVsRes
}

func testSingleMEV(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]testCaseMEV, cfg testMEVConfig, target string, resCh chan map[string][]testResult) error {
	singleTestResCh := make(chan testResult)
	allTestRes := []testResult{}

	// run all mev tests for a mev node, pushing each completed test to the channel until all are complete or timeout occurs
	go runMEVTest(ctx, queuedTestCases, allTestCases, cfg, target, singleTestResCh)
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

func runMEVTest(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]testCaseMEV, cfg testMEVConfig, target string, ch chan testResult) {
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

func mevPingTest(ctx context.Context, _ *testMEVConfig, target string) testResult {
	testRes := testResult{Name: "Ping"}

	client := http.Client{}
	targetEndpoint := fmt.Sprintf("%v/eth/v1/builder/status", target)
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
		return failedTestResult(testRes, errors.New(httpStatusError(resp.StatusCode)))
	}

	testRes.Verdict = testVerdictOk

	return testRes
}

func mevPingMeasureTest(ctx context.Context, _ *testMEVConfig, target string) testResult {
	testRes := testResult{Name: "PingMeasure"}

	var start time.Time
	var firstByte time.Duration

	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			firstByte = time.Since(start)
		},
	}

	start = time.Now()
	targetEndpoint := fmt.Sprintf("%v/eth/v1/builder/status", target)
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
		return failedTestResult(testRes, errors.New(httpStatusError(resp.StatusCode)))
	}

	if firstByte > thresholdMEVMeasurePoor {
		testRes.Verdict = testVerdictPoor
	} else if firstByte > thresholdMEVMeasureAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = Duration{firstByte}.String()

	return testRes
}
