// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"io"
	"sort"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"
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
		Long:  `Run multiple tests towards peer nodes. Verify if the current setup is suitable for mainnet cluster.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
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

func supportedPeersTestCases() map[testCaseName]func(*testPeersConfig) testResult {
	return map[testCaseName]func(*testPeersConfig) testResult{
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
	ctx, cancel := context.WithTimeout(parentCtx, cfg.Timeout)
	defer cancel()

	ch := make(chan testResult)
	res := testCategoryResult{
		TestsExecuted: make(map[string]testResult),
		CategoryName:  "peers",
	}

	startTime := time.Now()
	// run all peers tests, pushing each finished test until all are finished or timeout occurs
	go runAllPeers(ctx, queuedTests, testCases, cfg, ch)
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

	if cfg.OutputFile != "" {
		writeResultToFile(res, cfg.testConfig)
	}

	if !cfg.Quiet {
		writeResultToWriter(res, w)
	}

	return nil
}

func runAllPeers(_ context.Context, queuedTests []testCaseName, allTests map[testCaseName]func(*testPeersConfig) testResult, cfg testPeersConfig, ch chan testResult) {
	for _, t := range queuedTests {
		ch <- allTests[t](&cfg)
	}
}

func peersPing(config *testPeersConfig) testResult {
	//TODO(kalo): implement real ping
	return testResult{
		Verdict: testVerdictFail,
		Error:   errors.New("not implemented").Error(),
	}
}
