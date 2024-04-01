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
	cmd.Flags().StringVar(&config.APIAddress, "api-address", "127.0.0.1:3600", "Listening address (ip and port) for validator-facing traffic proxying the beacon-node API.")
}

func supportedValidatorTestCases() map[testCaseName]func(context.Context, *testValidatorConfig) testResult {
	return map[testCaseName]func(context.Context, *testValidatorConfig) testResult{
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
	timeoutCtx, cancel := context.WithTimeout(parentCtx, cfg.Timeout)
	defer cancel()

	ch := make(chan testResult)
	res := testCategoryResult{
		TestsExecuted: make(map[string]testResult),
		CategoryName:  "validator",
	}

	startTime := time.Now()
	// run all validator tests, pushing each finished test until all are finished or timeout occurs
	go runAllValidator(timeoutCtx, queuedTests, testCases, cfg, ch)

	testCounter := 0
outer:
	for {
		var name string
		select {
		case <-timeoutCtx.Done():
			name = queuedTests[testCounter].name
			res.TestsExecuted[name] = testResult{Verdict: testVerdictTimeout}
			break outer
		case result, ok := <-ch:
			if ok {
				name = queuedTests[testCounter].name
				testCounter++
				res.TestsExecuted[name] = result
			} else {
				break outer
			}
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

func runAllValidator(ctx context.Context, queuedTests []testCaseName, allTests map[testCaseName]func(context.Context, *testValidatorConfig) testResult, cfg testValidatorConfig, ch chan testResult) {
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
		return testResult{Verdict: testVerdictTimeout}
	default:
		return testResult{
			Verdict: testVerdictFail,
			Error:   errors.New("not implemented").Error(),
		}
	}
}
