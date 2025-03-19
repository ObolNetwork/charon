// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"io"
	"maps"
	"math"
	"math/rand"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

type testValidatorConfig struct {
	testConfig
	APIAddress       string
	LoadTestDuration time.Duration
}

const (
	thresholdValidatorMeasureAvg  = 50 * time.Millisecond
	thresholdValidatorMeasurePoor = 240 * time.Millisecond
	thresholdValidatorLoadAvg     = 50 * time.Millisecond
	thresholdValidatorLoadPoor    = 240 * time.Millisecond
)

func newTestValidatorCmd(runFunc func(context.Context, io.Writer, testValidatorConfig) (testCategoryResult, error)) *cobra.Command {
	var config testValidatorConfig

	cmd := &cobra.Command{
		Use:   "validator",
		Short: "Run multiple tests towards validator client",
		Long:  `Run multiple tests towards validator client. Verify that Charon can efficiently interact with its validator client.`,
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return mustOutputToFileOnQuiet(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := runFunc(cmd.Context(), cmd.OutOrStdout(), config)
			return err
		},
	}

	bindTestFlags(cmd, &config.testConfig)
	bindTestValidatorFlags(cmd, &config, "")

	return cmd
}

func bindTestValidatorFlags(cmd *cobra.Command, config *testValidatorConfig, flagsPrefix string) {
	cmd.Flags().StringVar(&config.APIAddress, flagsPrefix+"validator-api-address", "127.0.0.1:3600", "Listening address (ip and port) for validator-facing traffic proxying the beacon-node API.")
	cmd.Flags().DurationVar(&config.LoadTestDuration, flagsPrefix+"load-test-duration", 5*time.Second, "Time to keep running the load tests in seconds. For each second a new continuous ping instance is spawned.")
}

func supportedValidatorTestCases() map[testCaseName]func(context.Context, *testValidatorConfig) testResult {
	return map[testCaseName]func(context.Context, *testValidatorConfig) testResult{
		{name: "Ping", order: 1}:        validatorPingTest,
		{name: "PingMeasure", order: 2}: validatorPingMeasureTest,
		{name: "PingLoad", order: 3}:    validatorPingLoadTest,
	}
}

func runTestValidator(ctx context.Context, w io.Writer, cfg testValidatorConfig) (res testCategoryResult, err error) {
	log.Info(ctx, "Starting validator client test")

	testCases := supportedValidatorTestCases()
	queuedTests := filterTests(slices.Collect(maps.Keys(testCases)), cfg.testConfig)
	if len(queuedTests) == 0 {
		err = errors.New("test case not supported")
		return res, err
	}
	sortTests(queuedTests)

	timeoutCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	testResultsChan := make(chan map[string][]testResult)
	testResults := make(map[string][]testResult)
	startTime := time.Now()

	// run test suite for a single validator client
	go testSingleValidator(timeoutCtx, queuedTests, testCases, cfg, testResultsChan)

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

	res = testCategoryResult{
		CategoryName:  validatorTestCategory,
		Targets:       testResults,
		ExecutionTime: execTime,
		Score:         score,
	}

	if !cfg.Quiet {
		err = writeResultToWriter(res, w)
		if err != nil {
			return res, err
		}
	}

	if cfg.OutputJSON != "" {
		err = writeResultToFile(res, cfg.OutputJSON)
		if err != nil {
			return res, err
		}
	}

	return res, nil
}

// validator client tests

func testSingleValidator(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]func(context.Context, *testValidatorConfig) testResult, cfg testValidatorConfig, resCh chan map[string][]testResult) {
	defer close(resCh)
	singleTestResCh := make(chan testResult)
	allTestRes := []testResult{}
	// run all validator tests for a validator client, pushing each completed test to the channel until all are complete or timeout occurs
	go testValidator(ctx, queuedTestCases, allTestCases, cfg, singleTestResCh)

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
			testCounter++
			allTestRes = append(allTestRes, result)
		}
	}

	resCh <- map[string][]testResult{cfg.APIAddress: allTestRes}
}

func testValidator(ctx context.Context, queuedTests []testCaseName, allTests map[testCaseName]func(context.Context, *testValidatorConfig) testResult, cfg testValidatorConfig, ch chan testResult) {
	defer close(ch)
	for _, t := range queuedTests {
		select {
		case <-ctx.Done():
			return
		default:
			ch <- allTests[t](ctx, &cfg)
		}
	}
}

func validatorPingTest(ctx context.Context, conf *testValidatorConfig) testResult {
	testRes := testResult{Name: "Ping"}

	d := net.Dialer{Timeout: time.Second}
	conn, err := d.DialContext(ctx, "tcp", conf.APIAddress)
	if err != nil {
		return failedTestResult(testRes, err)
	}
	defer conn.Close()

	testRes.Verdict = testVerdictOk

	return testRes
}

func validatorPingMeasureTest(ctx context.Context, conf *testValidatorConfig) testResult {
	testRes := testResult{Name: "PingMeasure"}

	d := net.Dialer{Timeout: time.Second}
	before := time.Now()
	conn, err := d.DialContext(ctx, "tcp", conf.APIAddress)
	if err != nil {
		return failedTestResult(testRes, err)
	}
	defer conn.Close()
	rtt := time.Since(before)

	testRes = evaluateRTT(rtt, testRes, thresholdValidatorMeasureAvg, thresholdValidatorMeasurePoor)

	return testRes
}

func validatorPingLoadTest(ctx context.Context, conf *testValidatorConfig) testResult {
	log.Info(ctx, "Running ping load tests...",
		z.Any("duration", conf.LoadTestDuration),
		z.Any("target", conf.APIAddress),
	)
	testRes := testResult{Name: "PingLoad"}

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
				pingValidatorContinuously(pingCtx, conf.APIAddress, testResCh)
				wg.Done()
			}()
		case <-pingCtx.Done():
		}
	}
	wg.Wait()
	close(testResCh)
	log.Info(ctx, "Ping load tests finished", z.Any("target", conf.APIAddress))

	testRes = evaluateHighestRTTScores(testResCh, testRes, thresholdValidatorLoadAvg, thresholdValidatorLoadPoor)

	return testRes
}

// helper functions

func pingValidatorContinuously(ctx context.Context, address string, resCh chan<- time.Duration) {
	d := net.Dialer{Timeout: time.Second}
	for {
		before := time.Now()
		conn, err := d.DialContext(ctx, "tcp", address)
		if err != nil {
			return
		}
		rtt := time.Since(before)
		err = conn.Close()
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
