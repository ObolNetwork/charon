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

func supportedBeaconTestCases() map[testCaseName]func(context.Context, *testBeaconConfig) testResult {
	return map[testCaseName]func(context.Context, *testBeaconConfig) testResult{
		{name: "ping", order: 1}: beaconPing,
	}
}

func runTestBeacon(ctx context.Context, w io.Writer, cfg testBeaconConfig) (err error) {
	testCases := supportedBeaconTestCases()
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
		CategoryName:  "beacon",
	}

	startTime := time.Now()
	// run all beacon tests, pushing each finished test until all are finished or timeout occurs
	go runAllBeacon(timeoutCtx, queuedTests, testCases, cfg, ch)

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
			if !ok {
				break
			}
			name = queuedTests[testCounter].name
			testCounter++
			res.TestsExecuted[name] = result
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

func runAllBeacon(ctx context.Context, queuedTests []testCaseName, allTests map[testCaseName]func(context.Context, *testBeaconConfig) testResult, cfg testBeaconConfig, ch chan testResult) {
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

func beaconPing(ctx context.Context, _ *testBeaconConfig) testResult {
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
