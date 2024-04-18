// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"math/rand"
	"slices"
	"strings"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/peerinfo"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
)

type testPeersConfig struct {
	testConfig
	ENRs             []string
	P2P              p2p.Config
	Log              log.Config
	DataDir          string
	KeepAlive        time.Duration
	LoadTestDuration time.Duration
}

type testCasePeer func(context.Context, *testPeersConfig, host.Host, p2p.Peer) testResult

const (
	thresholdMeasureAvg = 200 * time.Millisecond
	thresholdMeasureBad = 500 * time.Millisecond
	thresholdLoadAvg    = 200 * time.Millisecond
	thresholdLoadBad    = 500 * time.Millisecond
)

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
	bindP2PFlags(cmd, &config.P2P)
	bindDataDirFlag(cmd.Flags(), &config.DataDir)
	bindTestLogFlags(cmd.Flags(), &config.Log)

	return cmd
}

func bindTestPeersFlags(cmd *cobra.Command, config *testPeersConfig) {
	const enrs = "enrs"
	cmd.Flags().StringSliceVar(&config.ENRs, enrs, nil, "[REQUIRED] Comma-separated list of each peer ENR address.")
	cmd.Flags().DurationVar(&config.KeepAlive, "keep-alive", 30*time.Minute, "Time to keep TCP node alive after test completion, so connection is open for other peers to test on their end.")
	cmd.Flags().DurationVar(&config.LoadTestDuration, "load-test-duration", 30*time.Second, "Time to keep running the load tests in seconds. For each second a new continuous ping instance is spawned.")
	mustMarkFlagRequired(cmd, enrs)
}

func bindTestLogFlags(flags *pflag.FlagSet, config *log.Config) {
	flags.StringVar(&config.Format, "log-format", "console", "Log format; console, logfmt or json")
	flags.StringVar(&config.Level, "log-level", "info", "Log level; debug, info, warn or error")
	flags.StringVar(&config.Color, "log-color", "auto", "Log color; auto, force, disable.")
	flags.StringVar(&config.LogOutputPath, "log-output-path", "", "Path in which to write on-disk logs.")
}

func supportedPeerTestCases() map[testCaseName]testCasePeer {
	return map[testCaseName]testCasePeer{
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

func startTCPNode(ctx context.Context, cfg testPeersConfig) (host.Host, func(), error) {
	var peers []p2p.Peer
	for i, e := range cfg.ENRs {
		record, err := enr.Parse(e)
		if err != nil {
			return nil, nil, errors.Wrap(err, "decode enr", z.Str("enr", e))
		}

		p, err := p2p.NewPeerFromENR(record, i)
		if err != nil {
			return nil, nil, err
		}

		peers = append(peers, p)
	}

	key, err := p2p.LoadPrivKey(cfg.DataDir)
	if err != nil {
		return nil, nil, err
	}

	r, err := enr.New(key)
	if err != nil {
		return nil, nil, err
	}

	mePeer, err := p2p.NewPeerFromENR(r, len(cfg.ENRs))
	if err != nil {
		return nil, nil, err
	}

	log.Info(ctx, "Self p2p name resolved", z.Any("name", mePeer.Name))

	peers = append(peers, mePeer)

	allENRs := cfg.ENRs
	allENRs = append(allENRs, r.String())
	slices.Sort(allENRs)
	allENRsString := strings.Join(allENRs, ",")
	allENRsHash := sha256.Sum256([]byte(allENRsString))

	return setupP2P(ctx, key, cfg.P2P, peers, allENRsHash[:])
}

func setupP2P(ctx context.Context, key *k1.PrivateKey, cfg p2p.Config, peers []p2p.Peer, enrsHash []byte) (host.Host, func(), error) {
	var peerIDs []peer.ID
	for _, p := range peers {
		peerIDs = append(peerIDs, p.ID)
	}

	if err := p2p.VerifyP2PKey(peers, key); err != nil {
		return nil, nil, err
	}

	relays, err := p2p.NewRelays(ctx, cfg.Relays, hex.EncodeToString(enrsHash))
	if err != nil {
		return nil, nil, err
	}

	connGater, err := p2p.NewConnGater(peerIDs, relays)
	if err != nil {
		return nil, nil, err
	}

	tcpNode, err := p2p.NewTCPNode(ctx, cfg, key, connGater, false)
	if err != nil {
		return nil, nil, err
	}

	p2p.RegisterConnectionLogger(ctx, tcpNode, peerIDs)

	for _, relay := range relays {
		relay := relay
		go p2p.NewRelayReserver(tcpNode, relay)(ctx)
	}

	go p2p.NewRelayRouter(tcpNode, peerIDs, relays)(ctx)

	// Register peerinfo server handler for identification to relays (but do not run peerinfo client).
	gitHash, _ := version.GitCommit()
	_ = peerinfo.New(tcpNode, peerIDs, version.Version, enrsHash, gitHash, nil, false)

	return tcpNode, func() {
		err := tcpNode.Close()
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Error(ctx, "Close TCP node", err)
		}
	}, nil
}

func pingPeerOnce(ctx context.Context, tcpNode host.Host, peer p2p.Peer) (ping.Result, error) {
	select {
	case <-ctx.Done():
		return ping.Result{}, ctx.Err()
	default:
		pingSvc := ping.NewPingService(tcpNode)
		pingCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		for {
			pingChan := pingSvc.Ping(pingCtx, peer.ID)
			select {
			case <-pingCtx.Done():
				return ping.Result{}, ctx.Err()
			case result := <-pingChan:
				return result, nil
			}
		}
	}
}

func pingPeerContinuously(ctx context.Context, tcpNode host.Host, peer p2p.Peer, resCh chan ping.Result) {
	for {
		select {
		case <-ctx.Done():
			select {
			case <-resCh:
				return
			default:
				close(resCh)
				return
			}
		default:
			r, err := pingPeerOnce(ctx, tcpNode, peer)
			if err != nil {
				return
			}
			resCh <- r
			awaitTime := rand.Intn(100) //nolint:gosec // weak generator is not an issue here
			time.Sleep(time.Duration(awaitTime) * time.Millisecond)
		}
	}
}

func runTestPeers(ctx context.Context, w io.Writer, cfg testPeersConfig) error {
	err := log.InitLogger(cfg.Log)
	if err != nil {
		return err
	}

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

	testResultsChan := make(chan map[string][]testResult)
	testResults := make(map[string][]testResult)

	tcpNode, shutdown, err := startTCPNode(ctx, cfg)
	if err != nil {
		return err
	}
	defer shutdown()

	g, _ := errgroup.WithContext(timeoutCtx)

	startTime := time.Now()
	g.Go(func() error {
		return testAllPeers(timeoutCtx, queuedTestsPeer, peerTestCases, cfg, tcpNode, testResultsChan)
	})
	g.Go(func() error { return testSelf(timeoutCtx, queuedTestsSelf, selfTestCases, cfg, testResultsChan) })

	done := make(chan bool, 1)
	go func() {
		for r := range testResultsChan {
			maps.Copy(testResults, r)
		}
		done <- true
	}()

	err = g.Wait()
	if err != nil {
		return errors.Wrap(err, "peers test errgroup")
	}
	execTime := Duration{time.Since(startTime)}
	close(testResultsChan)
	<-done

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

	log.Info(ctx, "Keeping TCP node alive for peers until keep-alive time is reached...")
	blockAndWait(ctx, cfg.KeepAlive)

	return nil
}

func testAllPeers(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]testCasePeer, cfg testPeersConfig, tcpNode host.Host, resCh chan map[string][]testResult) error {
	// run tests for all peer nodes
	res := make(map[string][]testResult)
	chs := []chan map[string][]testResult{}
	for _, enr := range cfg.ENRs {
		ch := make(chan map[string][]testResult)
		chs = append(chs, ch)
		go testSinglePeer(ctx, queuedTestCases, allTestCases, cfg, tcpNode, enr, ch)
	}

	for _, ch := range chs {
		result, ok := <-ch
		if !ok {
			break
		}
		maps.Copy(res, result)
	}

	resCh <- res

	return nil
}

func testSinglePeer(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]testCasePeer, cfg testPeersConfig, tcpNode host.Host, target string, resCh chan map[string][]testResult) {
	defer close(resCh)
	ch := make(chan testResult)
	res := []testResult{}
	enrTarget, err := enr.Parse(target)
	if err != nil {
		return
	}
	peerTarget, err := p2p.NewPeerFromENR(enrTarget, 0)
	if err != nil {
		return
	}

	// run all peers tests for a peer, pushing each completed test to the channel until all are complete or timeout occurs
	go runPeerTest(ctx, queuedTestCases, allTestCases, cfg, tcpNode, peerTarget, ch)
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
				continue
			}
			name = queuedTestCases[testCounter].name
			testCounter++
			result.Name = name
			res = append(res, result)
		}
	}

	nameENR := fmt.Sprintf("%v - %v", peerTarget.Name, target)
	resCh <- map[string][]testResult{nameENR: res}
}

func runPeerTest(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]testCasePeer, cfg testPeersConfig, tcpNode host.Host, target p2p.Peer, ch chan testResult) {
	defer close(ch)
	for _, t := range queuedTestCases {
		select {
		case <-ctx.Done():
			return
		default:
			ch <- allTestCases[t](ctx, &cfg, tcpNode, target)
		}
	}
}

func testSelf(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]func(context.Context, *testPeersConfig) testResult, cfg testPeersConfig, resCh chan map[string][]testResult) error {
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

	return nil
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

func peerPingTest(ctx context.Context, _ *testPeersConfig, tcpNode host.Host, peer p2p.Peer) testResult {
	tr := testResult{Name: "Ping"}

	ticker := time.NewTicker(1)
	defer ticker.Stop()

	for ; true; <-ticker.C {
		select {
		case <-ctx.Done():
			tr.Verdict = testVerdictFail
			tr.Error = errTimeoutInterrupted

			return tr
		default:
			ticker.Reset(3 * time.Second)
			result, err := pingPeerOnce(ctx, tcpNode, peer)
			if err != nil {
				tr.Verdict = testVerdictFail
				tr.Error = testResultError{err}

				return tr
			}

			if result.Error != nil {
				switch {
				case errors.Is(result.Error, context.DeadlineExceeded):
					tr.Verdict = testVerdictFail
					tr.Error = errTimeoutInterrupted

					return tr
				case p2p.IsRelayError(result.Error):
					tr.Verdict = testVerdictFail
					tr.Error = testResultError{result.Error}

					return tr
				default:
					log.Warn(ctx, "Ping to peer failed, retrying in 3 sec...", nil, z.Str("peer_name", peer.Name))
					continue
				}
			}

			tr.Verdict = testVerdictOk

			return tr
		}
	}

	tr.Verdict = testVerdictFail
	tr.Error = errNoTicker

	return tr
}

func peerPingMeasureTest(ctx context.Context, _ *testPeersConfig, tcpNode host.Host, peer p2p.Peer) testResult {
	tr := testResult{Name: "PingMeasure"}

	result, err := pingPeerOnce(ctx, tcpNode, peer)
	if err != nil {
		tr.Verdict = testVerdictFail
		tr.Error = testResultError{err}

		return tr
	}
	if result.Error != nil {
		tr.Verdict = testVerdictFail
		tr.Error = testResultError{result.Error}

		return tr
	}

	if result.RTT > thresholdMeasureBad {
		tr.Verdict = testVerdictBad
	} else if result.RTT > thresholdMeasureAvg {
		tr.Verdict = testVerdictAvg
	} else {
		tr.Verdict = testVerdictGood
	}
	tr.Measurement = Duration{result.RTT}.String()

	return tr
}

func peerPingLoadTest(ctx context.Context, cfg *testPeersConfig, tcpNode host.Host, peer p2p.Peer) testResult {
	log.Info(ctx, "Running ping load tests...",
		z.Any("duration", cfg.LoadTestDuration),
		z.Any("target", peer.Name),
	)
	tr := testResult{Name: "PingLoad"}

	deadlineC := time.After(cfg.LoadTestDuration)
	resCh := make(chan ping.Result, math.MaxInt16)
	pingCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	finished := false
	for !finished {
		select {
		case <-ctx.Done():
			finished = true
		case <-ticker.C:
			go pingPeerContinuously(pingCtx, tcpNode, peer, resCh)
		case <-deadlineC:
			finished = true
		}
	}
	cancel()

	highest := time.Duration(0)
	for val := range resCh {
		if val.RTT > highest {
			highest = val.RTT
		}
	}

	if highest > thresholdLoadBad {
		tr.Verdict = testVerdictBad
	} else if highest > thresholdLoadAvg {
		tr.Verdict = testVerdictAvg
	} else {
		tr.Verdict = testVerdictGood
	}
	tr.Measurement = Duration{highest}.String()

	return tr
}

func natOpenTest(ctx context.Context, _ *testPeersConfig) testResult {
	// TODO(kalo): implement real port check
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
