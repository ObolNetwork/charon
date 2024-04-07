// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"io"
	"sort"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"

	"github.com/obolnetwork/charon/app/errors"
)

type testBeaconConfig struct {
	testConfig
	Endpoints []string
}

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
		{name: "ping", order: 1}: beaconPing,
	}
}

func runTestBeacon(ctx context.Context, w io.Writer, cfg testBeaconConfig) (err error) {
	testCases := supportedBeaconTestCases()
	queuedTests := filterTests(maps.Keys(testCases), cfg.testConfig)
	if len(queuedTests) == 0 {
		return errors.New("test case not supported")
	}
	sortTests(queuedTests)
	sort.Slice(queuedTests, func(i, j int) bool {
		return queuedTests[i].order < queuedTests[j].order
	})

	parentCtx := ctx
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	timeoutCtx, cancel := context.WithTimeout(parentCtx, cfg.Timeout)
	defer cancel()

	ch := make(chan map[string][]testResult)
	testResults := make(map[string][]testResult)
	startTime := time.Now()
	finished := false
	// run all beacon tests, pushing each finished test until all are finished or timeout occurs
	go testAllBeacons(timeoutCtx, queuedTests, testCases, cfg, ch)

	for !finished {
		select {
		case <-ctx.Done():
			finished = true
		case result, ok := <-ch:
			if !ok {
				finished = true
			}
			maps.Copy(testResults, result)
		}
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
	// run all beacon tests, pushing each finished test until all are finished or timeout occurs
	res := make(map[string][]testResult)
	chs := []chan map[string][]testResult{}
	for _, enr := range cfg.Endpoints {
		ch := make(chan map[string][]testResult)
		chs = append(chs, ch)
		go testSingleBeacon(ctx, queuedTestCases, allTestCases, cfg, enr, ch)
	}

	for _, ch := range chs {
		for {
			// we are checking for context done inside the go routine
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
	// run all beacon tests, pushing each finished test until all are finished or timeout occurs
	go runBeaconTest(ctx, queuedTestCases, allTestCases, cfg, target, ch)

	testCounter := 0
	finished := false
	for !finished {
		var name string
		select {
		case <-ctx.Done():
			name = queuedTestCases[testCounter].name
			res = append(res, testResult{Name: name, Verdict: testVerdictFail, Error: "timeout"})
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

func beaconPing(ctx context.Context, _ *testBeaconConfig, _ string) testResult {
	// TODO(kalo): implement real ping
	select {
	case <-ctx.Done():
		return testResult{Verdict: testVerdictFail}
	default:
		return testResult{
			Verdict: testVerdictFail,
			Error:   errors.New("ping not implemented").Error(),
		}
	}
}
