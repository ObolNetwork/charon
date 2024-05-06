// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"io"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"

	"github.com/obolnetwork/charon/app/errors"
)

type testValidatorConfig struct {
	testConfig
	APIAddress string
}

func newTestValidatorCmd(runFunc func(context.Context, io.Writer, testValidatorConfig) error) *cobra.Command {
	var config testValidatorConfig

	cmd := &cobra.Command{
		Use:   "validator",
		Short: "Run multiple tests towards validator client",
		Long:  `Run multiple tests towards validator client. Verify that Charon can efficiently interact with other Charon peer nodes.`,
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return mustOutputToFileOnQuiet(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFunc(cmd.Context(), cmd.OutOrStdout(), config)
		},
	}

	bindTestFlags(cmd, &config.testConfig)
	bindTestValidatorFlags(cmd, &config)

	return cmd
}

func bindTestValidatorFlags(cmd *cobra.Command, config *testValidatorConfig) {
	cmd.Flags().StringVar(&config.APIAddress, "validator-api-address", "127.0.0.1:3600", "Listening address (ip and port) for validator-facing traffic proxying the beacon-node API.")
}

func supportedValidatorTestCases() map[testCaseName]func(context.Context, *testValidatorConfig) testResult {
	return map[testCaseName]func(context.Context, *testValidatorConfig) testResult{
		{name: "ping", order: 1}: validatorPing,
	}
}

func runTestValidator(ctx context.Context, w io.Writer, cfg testValidatorConfig) (err error) {
	testCases := supportedValidatorTestCases()
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

	// run test suite for a single validator client
	go testSingleValidator(timeoutCtx, queuedTests, testCases, cfg, resultsCh)

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
		CategoryName:  "validator",
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

func testSingleValidator(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]func(context.Context, *testValidatorConfig) testResult, cfg testValidatorConfig, resCh chan map[string][]testResult) {
	defer close(resCh)
	ch := make(chan testResult)
	res := []testResult{}
	// run all validator tests for a validator client, pushing each completed test to the channel until all are complete or timeout occurs
	go testValidator(ctx, queuedTestCases, allTestCases, cfg, ch)

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

	resCh <- map[string][]testResult{cfg.APIAddress: res}
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

func validatorPing(ctx context.Context, _ *testValidatorConfig) testResult {
	// TODO(kalo): implement real ping
	select {
	case <-ctx.Done():
		return testResult{Verdict: testVerdictFail}
	default:
		return testResult{
			Verdict: testVerdictFail,
			Error:   errNotImplemented,
		}
	}
}
