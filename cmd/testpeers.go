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
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
)

type testPeersConfig struct {
	testConfig
	ENRs                    []string
	P2P                     p2p.Config
	Log                     log.Config
	DataDir                 string
	KeepAlive               time.Duration
	LoadTestDuration        time.Duration
	DirectConnectionTimeout time.Duration
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
	cmd.Flags().DurationVar(&config.DirectConnectionTimeout, "direct-connection-timeout", 2*time.Minute, "Time to keep trying to establish direct connection to peer.")
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
		{name: "directConn", order: 4}:  peerDirectConnTest,
	}
}

func supportedSelfTestCases() map[testCaseName]func(context.Context, *testPeersConfig) testResult {
	return map[testCaseName]func(context.Context, *testPeersConfig) testResult{
		{name: "libp2pTCPPortOpenTest", order: 1}: libp2pTCPPortOpenTest,
	}
}

func startTCPNode(ctx context.Context, conf testPeersConfig) (host.Host, func(), error) {
	var p2pPeers []p2p.Peer
	for i, enrString := range conf.ENRs {
		enrRecord, err := enr.Parse(enrString)
		if err != nil {
			return nil, nil, errors.Wrap(err, "decode enr", z.Str("enr", enrString))
		}

		p2pPeer, err := p2p.NewPeerFromENR(enrRecord, i)
		if err != nil {
			return nil, nil, err
		}

		p2pPeers = append(p2pPeers, p2pPeer)
	}

	p2pPrivKey, err := p2p.LoadPrivKey(conf.DataDir)
	if err != nil {
		return nil, nil, err
	}

	meENR, err := enr.New(p2pPrivKey)
	if err != nil {
		return nil, nil, err
	}

	mePeer, err := p2p.NewPeerFromENR(meENR, len(conf.ENRs))
	if err != nil {
		return nil, nil, err
	}

	log.Info(ctx, "Self p2p name resolved", z.Any("name", mePeer.Name))

	p2pPeers = append(p2pPeers, mePeer)

	allENRs := conf.ENRs
	allENRs = append(allENRs, meENR.String())
	slices.Sort(allENRs)
	allENRsString := strings.Join(allENRs, ",")
	allENRsHash := sha256.Sum256([]byte(allENRsString))

	return setupP2P(ctx, p2pPrivKey, conf.P2P, p2pPeers, allENRsHash[:])
}

func setupP2P(ctx context.Context, privKey *k1.PrivateKey, conf p2p.Config, peers []p2p.Peer, enrsHash []byte) (host.Host, func(), error) {
	var peerIDs []peer.ID
	for _, peer := range peers {
		peerIDs = append(peerIDs, peer.ID)
	}

	if err := p2p.VerifyP2PKey(peers, privKey); err != nil {
		return nil, nil, err
	}

	relays, err := p2p.NewRelays(ctx, conf.Relays, hex.EncodeToString(enrsHash))
	if err != nil {
		return nil, nil, err
	}

	connGater, err := p2p.NewConnGater(peerIDs, relays)
	if err != nil {
		return nil, nil, err
	}

	tcpNode, err := p2p.NewTCPNode(ctx, conf, privKey, connGater, false)
	if err != nil {
		return nil, nil, err
	}

	p2p.RegisterConnectionLogger(ctx, tcpNode, peerIDs)

	for _, relay := range relays {
		relay := relay
		go p2p.NewRelayReserver(tcpNode, relay)(ctx)
	}

	go p2p.NewRelayRouter(tcpNode, peerIDs, relays)(ctx)

	return tcpNode, func() {
		err := tcpNode.Close()
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Error(ctx, "Close TCP node", err)
		}
	}, nil
}

func pingPeerOnce(ctx context.Context, tcpNode host.Host, peer p2p.Peer) (ping.Result, error) {
	pingSvc := ping.NewPingService(tcpNode)
	pingCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	pingChan := pingSvc.Ping(pingCtx, peer.ID)
	result, ok := <-pingChan
	if !ok {
		return ping.Result{}, errors.New("ping channel closed")
	}

	return result, nil
}

func pingPeerContinuously(ctx context.Context, tcpNode host.Host, peer p2p.Peer, resCh chan<- ping.Result) {
	for {
		r, err := pingPeerOnce(ctx, tcpNode, peer)
		if err != nil {
			return
		}

		select {
		case <-ctx.Done():
			return
		case resCh <- r:
			awaitTime := rand.Intn(100) //nolint:gosec // weak generator is not an issue here
			sleepWithContext(ctx, time.Duration(awaitTime)*time.Millisecond)
		}
	}
}

func sleepWithContext(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	select {
	case <-ctx.Done():
		if !timer.Stop() {
			<-timer.C
		}
	case <-timer.C:
	}
}

func runTestPeers(ctx context.Context, w io.Writer, conf testPeersConfig) error {
	peerTestCases := supportedPeerTestCases()
	queuedTestsPeer := filterTests(maps.Keys(peerTestCases), conf.testConfig)
	sortTests(queuedTestsPeer)

	selfTestCases := supportedSelfTestCases()
	queuedTestsSelf := filterTests(maps.Keys(selfTestCases), conf.testConfig)
	sortTests(queuedTestsSelf)

	if len(queuedTestsPeer) == 0 && len(queuedTestsSelf) == 0 {
		return errors.New("test case not supported")
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, conf.Timeout)
	defer cancel()

	testResultsChan := make(chan map[string][]testResult)
	testResults := make(map[string][]testResult)

	tcpNode, shutdown, err := startTCPNode(ctx, conf)
	if err != nil {
		return err
	}
	defer shutdown()

	group, _ := errgroup.WithContext(timeoutCtx)
	doneReading := make(chan bool)

	startTime := time.Now()
	group.Go(func() error {
		return testAllPeers(timeoutCtx, queuedTestsPeer, peerTestCases, conf, tcpNode, testResultsChan)
	})
	group.Go(func() error { return testSelf(timeoutCtx, queuedTestsSelf, selfTestCases, conf, testResultsChan) })

	go func() {
		for result := range testResultsChan {
			maps.Copy(testResults, result)
		}
		doneReading <- true
	}()

	err = group.Wait()
	execTime := Duration{time.Since(startTime)}
	if err != nil {
		return errors.Wrap(err, "peers test errgroup")
	}
	close(testResultsChan)
	<-doneReading

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

	if !conf.Quiet {
		err = writeResultToWriter(res, w)
		if err != nil {
			return err
		}
	}

	if conf.OutputToml != "" {
		err = writeResultToFile(res, conf.OutputToml)
		if err != nil {
			return err
		}
	}

	log.Info(ctx, "Keeping TCP node alive for peers until keep-alive time is reached...")
	blockAndWait(ctx, conf.KeepAlive)

	return nil
}

func testAllPeers(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]testCasePeer, conf testPeersConfig, tcpNode host.Host, allPeersResCh chan map[string][]testResult) error {
	// run tests for all peer nodes
	allPeersRes := make(map[string][]testResult)
	singlePeerResCh := make(chan map[string][]testResult)
	group, _ := errgroup.WithContext(ctx)

	for _, enr := range conf.ENRs {
		currENR := enr // TODO: can be removed after go1.22 version bump
		group.Go(func() error {
			return testSinglePeer(ctx, queuedTestCases, allTestCases, conf, tcpNode, currENR, singlePeerResCh)
		})
	}

	doneReading := make(chan bool)
	go func() {
		for singlePeerRes := range singlePeerResCh {
			maps.Copy(allPeersRes, singlePeerRes)
		}
		doneReading <- true
	}()

	err := group.Wait()
	if err != nil {
		return errors.Wrap(err, "peers test errgroup")
	}
	close(singlePeerResCh)
	<-doneReading

	allPeersResCh <- allPeersRes

	return nil
}

func testSinglePeer(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]testCasePeer, conf testPeersConfig, tcpNode host.Host, target string, allTestResCh chan map[string][]testResult) error {
	singleTestResCh := make(chan testResult)
	allTestRes := []testResult{}
	enrTarget, err := enr.Parse(target)
	if err != nil {
		return err
	}
	peerTarget, err := p2p.NewPeerFromENR(enrTarget, 0)
	if err != nil {
		return err
	}

	// run all peers tests for a peer, pushing each completed test to the channel until all are complete or timeout occurs
	go runPeerTest(ctx, queuedTestCases, allTestCases, conf, tcpNode, peerTarget, singleTestResCh)
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
				continue
			}
			testName = queuedTestCases[testCounter].name
			testCounter++
			result.Name = testName
			allTestRes = append(allTestRes, result)
		}
	}

	nameENR := fmt.Sprintf("%v - %v", peerTarget.Name, target)
	allTestResCh <- map[string][]testResult{nameENR: allTestRes}

	return nil
}

func runPeerTest(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]testCasePeer, conf testPeersConfig, tcpNode host.Host, target p2p.Peer, testResCh chan testResult) {
	defer close(testResCh)
	for _, t := range queuedTestCases {
		select {
		case <-ctx.Done():
			return
		default:
			testResCh <- allTestCases[t](ctx, &conf, tcpNode, target)
		}
	}
}

func testSelf(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]func(context.Context, *testPeersConfig) testResult, conf testPeersConfig, allTestResCh chan map[string][]testResult) error {
	singleTestResCh := make(chan testResult)
	allTestRes := []testResult{}
	go runSelfTest(ctx, queuedTestCases, allTestCases, conf, singleTestResCh)

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
				continue
			}
			testName = queuedTestCases[testCounter].name
			testCounter++
			result.Name = testName
			allTestRes = append(allTestRes, result)
		}
	}

	allTestResCh <- map[string][]testResult{"self": allTestRes}

	return nil
}

func runSelfTest(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]func(context.Context, *testPeersConfig) testResult, conf testPeersConfig, ch chan testResult) {
	defer close(ch)
	for _, t := range queuedTestCases {
		select {
		case <-ctx.Done():
			return
		default:
			ch <- allTestCases[t](ctx, &conf)
		}
	}
}

func peerPingTest(ctx context.Context, _ *testPeersConfig, tcpNode host.Host, peer p2p.Peer) testResult {
	testRes := testResult{Name: "Ping"}

	ticker := time.NewTicker(1)
	defer ticker.Stop()

	for ; true; <-ticker.C {
		select {
		case <-ctx.Done():
			return failedTestResult(testRes, errTimeoutInterrupted)
		default:
			ticker.Reset(3 * time.Second)
			result, err := pingPeerOnce(ctx, tcpNode, peer)
			if err != nil {
				return failedTestResult(testRes, err)
			}

			if result.Error != nil {
				switch {
				case errors.Is(result.Error, context.DeadlineExceeded):
					return failedTestResult(testRes, errTimeoutInterrupted)
				case p2p.IsRelayError(result.Error):
					return failedTestResult(testRes, result.Error)
				default:
					log.Warn(ctx, "Ping to peer failed, retrying in 3 sec...", nil, z.Str("peer_name", peer.Name))
					continue
				}
			}

			testRes.Verdict = testVerdictOk

			return testRes
		}
	}

	testRes.Verdict = testVerdictFail
	testRes.Error = errNoTicker

	return testRes
}

func peerPingMeasureTest(ctx context.Context, _ *testPeersConfig, tcpNode host.Host, peer p2p.Peer) testResult {
	testRes := testResult{Name: "PingMeasure"}

	result, err := pingPeerOnce(ctx, tcpNode, peer)
	if err != nil {
		return failedTestResult(testRes, err)
	}
	if result.Error != nil {
		return failedTestResult(testRes, result.Error)
	}

	if result.RTT > thresholdMeasureBad {
		testRes.Verdict = testVerdictBad
	} else if result.RTT > thresholdMeasureAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = Duration{result.RTT}.String()

	return testRes
}

func peerPingLoadTest(ctx context.Context, conf *testPeersConfig, tcpNode host.Host, peer p2p.Peer) testResult {
	log.Info(ctx, "Running ping load tests...",
		z.Any("duration", conf.LoadTestDuration),
		z.Any("target", peer.Name),
	)
	testRes := testResult{Name: "PingLoad"}

	testResCh := make(chan ping.Result, math.MaxInt16)
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
				pingPeerContinuously(pingCtx, tcpNode, peer, testResCh)
				wg.Done()
			}()
		case <-pingCtx.Done():
		}
	}
	wg.Wait()
	close(testResCh)
	log.Info(ctx, "Ping load tests finished", z.Any("target", peer.Name))

	highestRTT := time.Duration(0)
	for val := range testResCh {
		if val.RTT > highestRTT {
			highestRTT = val.RTT
		}
	}
	if highestRTT > thresholdLoadBad {
		testRes.Verdict = testVerdictBad
	} else if highestRTT > thresholdLoadAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = Duration{highestRTT}.String()

	return testRes
}

func dialLibp2pTCPIP(ctx context.Context, address string) error {
	d := net.Dialer{Timeout: time.Second}
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return errors.Wrap(err, "net dial")
	}
	defer conn.Close()
	buf := new(strings.Builder)
	_, err = io.CopyN(buf, conn, 19)
	if err != nil {
		return errors.Wrap(err, "io copy")
	}
	if !strings.Contains(buf.String(), "/multistream/1.0.0") {
		return errors.New("multistream not found", z.Any("found", buf.String()), z.Any("address", address))
	}

	err = conn.Close()
	if err != nil {
		return errors.Wrap(err, "close conn")
	}

	return nil
}

func peerDirectConnTest(ctx context.Context, conf *testPeersConfig, tcpNode host.Host, p2pPeer p2p.Peer) testResult {
	testRes := testResult{Name: "DirectConn"}

	log.Info(ctx, "Trying to establish direct connection...",
		z.Any("timeout", conf.DirectConnectionTimeout),
		z.Any("target", p2pPeer.Name))

	var err error
	for i := 0; i < int(conf.DirectConnectionTimeout); i++ {
		err = tcpNode.Connect(network.WithForceDirectDial(ctx, "relay_to_direct"), peer.AddrInfo{ID: p2pPeer.ID})
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return failedTestResult(testRes, err)
	}
	log.Info(ctx, "Direct connection established", z.Any("target", p2pPeer.Name))

	conns := tcpNode.Network().ConnsToPeer(p2pPeer.ID)
	if len(conns) < 2 {
		return failedTestResult(testRes, errors.New("expected 2 connections to peer (relay and direct)", z.Int("connections", len(conns))))
	}

	testRes.Verdict = testVerdictOk

	return testRes
}

func libp2pTCPPortOpenTest(ctx context.Context, cfg *testPeersConfig) testResult {
	testRes := testResult{Name: "Libp2pTCPPortOpen"}

	group, _ := errgroup.WithContext(ctx)

	for _, addr := range cfg.P2P.TCPAddrs {
		addrVal := addr
		group.Go(func() error { return dialLibp2pTCPIP(ctx, addrVal) })
	}

	err := group.Wait()
	if err != nil {
		return failedTestResult(testRes, err)
	}

	testRes.Verdict = testVerdictOk

	return testRes
}
