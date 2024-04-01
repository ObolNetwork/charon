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

type testValidatorConfig struct {
	testConfig
	APIAddress string
}

func newTestValidatorCmd(runFunc func(context.Context, io.Writer, testValidatorConfig) error) *cobra.Command {
	var config testValidatorConfig

	cmd := &cobra.Command{
		Use:   "validator",
		Short: "Run multiple tests towards validator client",
		Long:  `Run multiple tests towards validator client. Verify if the current setup is suitable for mainnet cluster.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.Context(), cmd.OutOrStdout(), config)
		},
	}

	bindTestFlags(cmd, &config.testConfig)
	bindTestValidatorFlags(cmd, &config)

	return cmd
}

func bindTestValidatorFlags(cmd *cobra.Command, config *testValidatorConfig) {
	cmd.Flags().StringVar(&config.APIAddress, "api-address", "127.0.0.1:3600", "Listening address (ip and port) for validator-facing traffic proxying the beacon-node API.")
}

func supportedValidatorTestCases() map[testCaseName]func(*testValidatorConfig) testResult {
	return map[testCaseName]func(*testValidatorConfig) testResult{
		{name: "ping", order: 1}: validatorPing,
	}
}

func runTestValidator(ctx context.Context, w io.Writer, cfg testValidatorConfig) (err error) {
	testCases := supportedValidatorTestCases()
	supportedTestCases := maps.Keys(testCases)

	queuedTests, err := filterTests(supportedTestCases, cfg.testConfig)
	if err != nil {
		return err
	}
	sort.Slice(queuedTests, func(i, j int) bool {
		return queuedTests[i].order < queuedTests[j].order
	})

	parentCtx := ctx
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(parentCtx, cfg.Timeout)
	defer cancel()

	ch := make(chan testResult)
	res := testCategoryResult{
		TestsExecuted: make(map[string]testResult),
		CategoryName:  "validator",
	}

	startTime := time.Now()
	// run all validator tests, pushing each finished test until all are finished or timeout occurs
	go runAllValidator(ctx, queuedTests, testCases, cfg, ch)
outer:
	for _, qt := range queuedTests {
		select {
		case <-ctx.Done():
			res.TestsExecuted[qt.name] = testResult{Verdict: testVerdictTimeout}
			break outer
		case result := <-ch:
			res.TestsExecuted[qt.name] = result
		}
	}

	res.ExecutionTime = Duration{time.Since(startTime)}
	res.Score = calculateScore(res.TestsExecuted)

	if !cfg.Quiet {
		err = writeResultToWriter(res, w)
		if err != nil {
			return err
		}
	}

	if cfg.OutputFile != "" {
		err = writeResultToFile(res, cfg.testConfig)
		if err != nil {
			return err
		}
	}

	return nil
}

func runAllValidator(_ context.Context, queuedTests []testCaseName, allTests map[testCaseName]func(*testValidatorConfig) testResult, cfg testValidatorConfig, ch chan testResult) {
	for _, t := range queuedTests {
		ch <- allTests[t](&cfg)
	}
}

func validatorPing(_ *testValidatorConfig) testResult {
	// TODO(kalo): implement real ping
	return testResult{
		Verdict: testVerdictFail,
		Error:   errors.New("not implemented").Error(),
	}
}
