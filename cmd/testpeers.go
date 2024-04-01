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

type testPeersConfig struct {
	testConfig
	ENRs []string
}

func newTestPeersCmd(runFunc func(context.Context, io.Writer, testPeersConfig) error) *cobra.Command {
	var config testPeersConfig

	cmd := &cobra.Command{
		Use:   "peers",
		Short: "Run multiple tests towards peer nodes",
		Long:  `Run multiple tests towards peer nodes. Verify that Charon can efficiently interact with Validator Client.`,
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return mustOutputToFileOnQuiet(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFunc(cmd.Context(), cmd.OutOrStdout(), config)
		},
	}

	bindTestFlags(cmd, &config.testConfig)
	bindTestPeersFlags(cmd, &config)

	return cmd
}

func bindTestPeersFlags(cmd *cobra.Command, config *testPeersConfig) {
	const enrs = "enrs"
	cmd.Flags().StringSliceVar(&config.ENRs, "enrs", nil, "[REQUIRED] Comma-separated list of each peer ENR address.")
	mustMarkFlagRequired(cmd, enrs)
}

func supportedPeersTestCases() map[testCaseName]func(context.Context, *testPeersConfig) testResult {
	return map[testCaseName]func(context.Context, *testPeersConfig) testResult{
		{name: "ping", order: 1}: peersPing,
	}
}

func runTestPeers(ctx context.Context, w io.Writer, cfg testPeersConfig) (err error) {
	testCases := supportedPeersTestCases()
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
		CategoryName:  "peers",
	}

	startTime := time.Now()
	// run all peers tests, pushing each finished test until all are finished or timeout occurs
	go runAllPeers(timeoutCtx, queuedTests, testCases, cfg, ch)

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

func runAllPeers(ctx context.Context, queuedTests []testCaseName, allTests map[testCaseName]func(context.Context, *testPeersConfig) testResult, cfg testPeersConfig, ch chan testResult) {
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

func peersPing(ctx context.Context, _ *testPeersConfig) testResult {
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
