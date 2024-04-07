// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"io"
	"math/rand"
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

func supportedPeerTestCases() map[testCaseName]func(context.Context, *testPeersConfig, string) testResult {
	return map[testCaseName]func(context.Context, *testPeersConfig, string) testResult{
		{name: "ping", order: 1}:        peerPingTest,
		{name: "pingMeasure", order: 2}: peerPingMeasureTest,
		{name: "pingLoad", order: 3}:    peerPingLoadTest,
	}
}

func supportedSelfTestCases() map[testCaseName]func(context.Context, *testPeersConfig) testResult {
	return map[testCaseName]func(context.Context, *testPeersConfig) testResult{
		{name: "natOpen", order: 1}: natOpenTest,
	}
}

func runTestPeers(ctx context.Context, w io.Writer, cfg testPeersConfig) (err error) {
	peerTestCases := supportedPeerTestCases()
	queuedTestsPeer := filterTests(maps.Keys(peerTestCases), cfg.testConfig)
	sortTests(queuedTestsPeer)

	selfTestCases := supportedSelfTestCases()
	queuedTestsSelf := filterTests(maps.Keys(selfTestCases), cfg.testConfig)
	sortTests(queuedTestsSelf)

	if len(queuedTestsPeer) == 0 && len(queuedTestsSelf) == 0 {
		return errors.New("test case not supported")
	}

	parentCtx := ctx
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	timeoutCtx, cancel := context.WithTimeout(parentCtx, cfg.Timeout)
	defer cancel()

	selfCh := make(chan map[string][]testResult)
	peersCh := make(chan map[string][]testResult)
	testResults := make(map[string][]testResult)
	var peersFinished, selfFinished bool

	startTime := time.Now()
	go testAllPeers(timeoutCtx, queuedTestsPeer, peerTestCases, cfg, peersCh)
	go testSelf(timeoutCtx, queuedTestsSelf, selfTestCases, cfg, selfCh)

	for !peersFinished || !selfFinished {
		select {
		case <-ctx.Done():
			peersFinished = true
			selfFinished = true
		case result, ok := <-selfCh:
			if !ok {
				selfFinished = true
				break
			}
			maps.Copy(testResults, result)
		case result, ok := <-peersCh:
			if !ok {
				peersFinished = true
				break
			}
			maps.Copy(testResults, result)
		}
	}
	execTime := Duration{time.Since(startTime)}

	// use lowest score as score of all
	var score categoryScore
	for _, t := range testResults {
		targetScore := calculateScore(t)
		if score == "" || score < targetScore {
			score = targetScore
		}
	}

	res := testCategoryResult{
		CategoryName:  "peers",
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

func testAllPeers(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]func(context.Context, *testPeersConfig, string) testResult, cfg testPeersConfig, resCh chan map[string][]testResult) {
	defer close(resCh)
	// run all peers tests, pushing each finished test until all are finished or timeout occurs
	res := make(map[string][]testResult)
	chs := []chan map[string][]testResult{}
	for _, enr := range cfg.ENRs {
		ch := make(chan map[string][]testResult)
		chs = append(chs, ch)
		go testSinglePeer(ctx, queuedTestCases, allTestCases, cfg, enr, ch)
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

func testSinglePeer(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]func(context.Context, *testPeersConfig, string) testResult, cfg testPeersConfig, target string, resCh chan map[string][]testResult) {
	defer close(resCh)
	ch := make(chan testResult)
	res := []testResult{}
	// run all peers tests, pushing each finished test until all are finished or timeout occurs
	go runPeerTest(ctx, queuedTestCases, allTestCases, cfg, target, ch)

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
				continue
			}
			name = queuedTestCases[testCounter].name
			testCounter++
			result.Name = name
			res = append(res, result)
		}
	}

	resCh <- map[string][]testResult{target: res}
}

func runPeerTest(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]func(context.Context, *testPeersConfig, string) testResult, cfg testPeersConfig, target string, ch chan testResult) {
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

func testSelf(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]func(context.Context, *testPeersConfig) testResult, cfg testPeersConfig, resCh chan map[string][]testResult) {
	defer close(resCh)
	ch := make(chan testResult)
	res := []testResult{}
	go runSelfTest(ctx, queuedTestCases, allTestCases, cfg, ch)

	testCounter := 0
	finished := false
	for !finished {
		var name string
		select {
		case <-ctx.Done():
			name = queuedTestCases[testCounter].name
			res = append(res, testResult{Name: name, Verdict: testVerdictFail})
			finished = true
		case result, ok := <-ch:
			if !ok {
				finished = true
				continue
			}
			name = queuedTestCases[testCounter].name
			testCounter++
			result.Name = name
			res = append(res, result)
		}
	}

	resCh <- map[string][]testResult{"self": res}
}

func runSelfTest(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]func(context.Context, *testPeersConfig) testResult, cfg testPeersConfig, ch chan testResult) {
	defer close(ch)
	for _, t := range queuedTestCases {
		select {
		case <-ctx.Done():
			return
		default:
			ch <- allTestCases[t](ctx, &cfg)
		}
	}
}

func peerPingTest(ctx context.Context, _ *testPeersConfig, _ string) testResult {
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

func peerPingMeasureTest(ctx context.Context, _ *testPeersConfig, _ string) testResult {
	// TODO(kalo): implement real ping measure
	s := rand.Int31n(300) + 100 //nolint: gosec // it's only temporary to showcase timeouts
	time.Sleep(time.Duration(s) * time.Millisecond)
	select {
	case <-ctx.Done():
		return testResult{Verdict: testVerdictFail}
	default:
		return testResult{
			Verdict:     testVerdictFail,
			Measurement: "10ms",
			Error:       errors.New("pingMeasure not implemented").Error(),
		}
	}
}

func peerPingLoadTest(ctx context.Context, _ *testPeersConfig, _ string) testResult {
	// TODO(kalo): implement real ping load
	select {
	case <-ctx.Done():
		return testResult{Verdict: testVerdictFail}
	default:
		return testResult{
			Verdict: testVerdictFail,
			Error:   errors.New("pingLoad not implemented").Error(),
		}
	}
}

func natOpenTest(ctx context.Context, _ *testPeersConfig) testResult {
	// TODO(kalo): implement real port check
	select {
	case <-ctx.Done():
		return testResult{Verdict: testVerdictFail}
	default:
		return testResult{
			Verdict: testVerdictFail,
			Error:   errors.New("natOpen not implemented").Error(),
		}
	}
}
