// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptrace"
	"slices"
	"strconv"
	"strings"
	"time"

	builderspec "github.com/attestantio/go-builder-client/spec"
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2a "github.com/attestantio/go-eth2-client/spec/altair"
	eth2e "github.com/attestantio/go-eth2-client/spec/electra"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

type testMEVConfig struct {
	testConfig

	Endpoints          []string
	BeaconNodeEndpoint string
	LoadTest           bool
	NumberOfPayloads   uint
}

type testCaseMEV func(context.Context, *testMEVConfig, string) testResult

const (
	thresholdMEVMeasureAvg  = 40 * time.Millisecond
	thresholdMEVMeasurePoor = 100 * time.Millisecond
	thresholdMEVBlockAvg    = 500 * time.Millisecond
	thresholdMEVBlockPoor   = 800 * time.Millisecond
)

var errStatusCodeNot200 = errors.New("status code not 200 OK")

func newTestMEVCmd(runFunc func(context.Context, io.Writer, testMEVConfig) (testCategoryResult, error)) *cobra.Command {
	var config testMEVConfig

	cmd := &cobra.Command{
		Use:   "mev",
		Short: "Run multiple tests towards MEV relays",
		Long:  `Run multiple tests towards MEV relays. Verify that Charon can efficiently interact with MEV relay(s).`,
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return mustOutputToFileOnQuiet(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := runFunc(cmd.Context(), cmd.OutOrStdout(), config)
			return err
		},
	}

	bindTestFlags(cmd, &config.testConfig)
	bindTestMEVFlags(cmd, &config, "")

	wrapPreRunE(cmd, func(cmd *cobra.Command, _ []string) error {
		loadTest := cmd.Flags().Lookup("load-test").Value.String()
		beaconNodeEndpoint := cmd.Flags().Lookup("beacon-node-endpoint").Value.String()

		if loadTest == "true" && beaconNodeEndpoint == "" {
			return errors.New("beacon-node-endpoint should be specified when load-test is")
		}

		if loadTest == "false" && beaconNodeEndpoint != "" {
			return errors.New("beacon-node-endpoint should be used only when load-test is")
		}

		return nil
	})

	return cmd
}

func bindTestMEVFlags(cmd *cobra.Command, config *testMEVConfig, flagsPrefix string) {
	cmd.Flags().StringSliceVar(&config.Endpoints, flagsPrefix+"endpoints", nil, "Comma separated list of one or more MEV relay endpoint URLs.")
	cmd.Flags().StringVar(&config.BeaconNodeEndpoint, flagsPrefix+"beacon-node-endpoint", "", "[REQUIRED] Beacon node endpoint URL used for block creation test.")
	cmd.Flags().BoolVar(&config.LoadTest, flagsPrefix+"load-test", false, "Enable load test.")
	cmd.Flags().UintVar(&config.NumberOfPayloads, flagsPrefix+"number-of-payloads", 1, "Increases the accuracy of the load test by asking for multiple payloads. Increases test duration.")
	mustMarkFlagRequired(cmd, flagsPrefix+"endpoints")
}

func supportedMEVTestCases() map[testCaseName]testCaseMEV {
	return map[testCaseName]testCaseMEV{
		{name: "Ping", order: 1}:        mevPingTest,
		{name: "PingMeasure", order: 2}: mevPingMeasureTest,
		{name: "CreateBlock", order: 3}: mevCreateBlockTest,
	}
}

func runTestMEV(ctx context.Context, w io.Writer, cfg testMEVConfig) (res testCategoryResult, err error) {
	log.Info(ctx, "Starting MEV relays test")

	testCases := supportedMEVTestCases()

	queuedTests := filterTests(slices.Collect(maps.Keys(testCases)), cfg.testConfig)
	if len(queuedTests) == 0 {
		return res, errors.New("test case not supported")
	}

	sortTests(queuedTests)

	timeoutCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	testResultsChan := make(chan map[string][]testResult)
	testResults := make(map[string][]testResult)
	startTime := time.Now()

	// run test suite for all mev nodes
	go testAllMEVs(timeoutCtx, queuedTests, testCases, cfg, testResultsChan)

	for result := range testResultsChan {
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

	res = testCategoryResult{
		CategoryName:  mevTestCategory,
		Targets:       testResults,
		ExecutionTime: execTime,
		Score:         score,
	}

	if !cfg.Quiet {
		err = writeResultToWriter(res, w)
		if err != nil {
			return res, err
		}
	}

	if cfg.OutputJSON != "" {
		err = writeResultToFile(res, cfg.OutputJSON)
		if err != nil {
			return res, err
		}
	}

	if cfg.Publish {
		err = publishResultToObolAPI(ctx, allCategoriesResult{MEV: res}, cfg.PublishAddr, cfg.PublishPrivateKeyFile)
		if err != nil {
			return res, err
		}
	}

	return res, nil
}

// mev relays tests

func testAllMEVs(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]testCaseMEV, conf testMEVConfig, allMEVsResCh chan map[string][]testResult) {
	defer close(allMEVsResCh)
	// run tests for all mev nodes
	allMEVsRes := make(map[string][]testResult)
	singleMEVResCh := make(chan map[string][]testResult)
	group, _ := errgroup.WithContext(ctx)

	for _, endpoint := range conf.Endpoints {
		group.Go(func() error {
			return testSingleMEV(ctx, queuedTestCases, allTestCases, conf, endpoint, singleMEVResCh)
		})
	}

	doneReading := make(chan bool)

	go func() {
		for singleMEVRes := range singleMEVResCh {
			maps.Copy(allMEVsRes, singleMEVRes)
		}

		doneReading <- true
	}()

	err := group.Wait()
	if err != nil {
		return
	}

	close(singleMEVResCh)
	<-doneReading

	allMEVsResCh <- allMEVsRes
}

func testSingleMEV(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]testCaseMEV, cfg testMEVConfig, target string, resCh chan map[string][]testResult) error {
	singleTestResCh := make(chan testResult)
	allTestRes := []testResult{}

	// run all mev tests for a mev node, pushing each completed test to the channel until all are complete or timeout occurs
	go runMEVTest(ctx, queuedTestCases, allTestCases, cfg, target, singleTestResCh)

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
				break
			}

			testCounter++

			allTestRes = append(allTestRes, result)
		}
	}

	relayName := formatMEVRelayName(target)
	resCh <- map[string][]testResult{relayName: allTestRes}

	return nil
}

func runMEVTest(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]testCaseMEV, cfg testMEVConfig, target string, ch chan testResult) {
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

func mevPingTest(ctx context.Context, _ *testMEVConfig, target string) testResult {
	testRes := testResult{Name: "Ping"}

	client := http.Client{}
	targetEndpoint := fmt.Sprintf("%v/eth/v1/builder/status", target)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetEndpoint, nil)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return failedTestResult(testRes, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode > 399 {
		return failedTestResult(testRes, errors.New(httpStatusError(resp.StatusCode)))
	}

	testRes.Verdict = testVerdictOk

	return testRes
}

func mevPingMeasureTest(ctx context.Context, _ *testMEVConfig, target string) testResult {
	testRes := testResult{Name: "PingMeasure"}

	rtt, err := requestRTT(ctx, fmt.Sprintf("%v/eth/v1/builder/status", target), http.MethodGet, nil, 200)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	testRes = evaluateRTT(rtt, testRes, thresholdMEVMeasureAvg, thresholdMEVMeasurePoor)

	return testRes
}

func mevCreateBlockTest(ctx context.Context, conf *testMEVConfig, target string) testResult {
	testRes := testResult{Name: "CreateBlock"}

	if !conf.LoadTest {
		testRes.Verdict = testVerdictSkipped
		return testRes
	}

	latestBlock, err := latestBeaconBlock(ctx, conf.BeaconNodeEndpoint)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	// wait for beginning of next slot, as the block for current one might have already been proposed
	latestBlockTSUnix, err := strconv.ParseInt(latestBlock.Body.ExecutionPayload.Timestamp, 10, 64)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	latestBlockTS := time.Unix(latestBlockTSUnix, 0)

	nextBlockTS := latestBlockTS.Add(slotTime)
	for time.Now().Before(nextBlockTS) && ctx.Err() == nil {
		sleepWithContext(ctx, time.Millisecond)
	}

	latestSlot, err := strconv.ParseInt(latestBlock.Slot, 10, 64)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	nextSlot := latestSlot + 1
	epoch := nextSlot / slotsInEpoch

	proposerDuties, err := fetchProposersForEpoch(ctx, conf, epoch)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	allBlocksRTT := []time.Duration{}

	log.Info(ctx, "Starting attempts for block creation", z.Any("mev_relay", target), z.Any("blocks", conf.NumberOfPayloads))

	for ctx.Err() == nil {
		startIteration := time.Now()

		rtt, err := createMEVBlock(ctx, conf, target, nextSlot, latestBlock, proposerDuties)
		if err != nil {
			return failedTestResult(testRes, err)
		}

		allBlocksRTT = append(allBlocksRTT, rtt)
		if len(allBlocksRTT) == int(conf.NumberOfPayloads) {
			break
		}
		// wait for the next slot - time it took createMEVBlock - 1 sec
		sleepWithContext(ctx, slotTime-time.Since(startIteration)%slotTime-time.Second)
		startBeaconBlockFetch := time.Now()
		// get the new latest block, produced during 'nextSlot'
		latestBlock, err = latestBeaconBlock(ctx, conf.BeaconNodeEndpoint)
		if err != nil {
			return failedTestResult(testRes, err)
		}

		latestSlot, err := strconv.ParseInt(latestBlock.Slot, 10, 64)
		if err != nil {
			return failedTestResult(testRes, err)
		}

		nextSlot = latestSlot + 1
		// wait 1 second - the time it took to fetch the latest block
		sleepWithContext(ctx, time.Second-time.Since(startBeaconBlockFetch))
	}

	totalRTT := time.Duration(0)
	for _, rtt := range allBlocksRTT {
		totalRTT += rtt
	}

	averageRTT := totalRTT / time.Duration(len(allBlocksRTT))

	testRes = evaluateRTT(averageRTT, testRes, thresholdMEVBlockAvg, thresholdMEVBlockPoor)

	return testRes
}

// helper functions

// Shorten the hash of the MEV relay endpoint
// Example: https://0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae@boost-relay.flashbots.net
// to https://0xac6e...37ae@boost-relay.flashbots.net
func formatMEVRelayName(urlString string) string {
	splitScheme := strings.Split(urlString, "://")
	if len(splitScheme) == 1 {
		return urlString
	}

	hashSplit := strings.Split(splitScheme[1], "@")
	if len(hashSplit) == 1 {
		return urlString
	}

	hash := hashSplit[0]
	if !strings.HasPrefix(hash, "0x") || len(hash) < 18 {
		return urlString
	}

	hashShort := hash[:6] + "..." + hash[len(hash)-4:]

	return splitScheme[0] + "://" + hashShort + "@" + hashSplit[1]
}

func getBlockHeader(ctx context.Context, target string, nextSlot int64, blockHash string, validatorPubKey string) (builderspec.VersionedSignedBuilderBid, time.Duration, error) {
	var (
		start     time.Time
		firstByte time.Duration
	)

	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			firstByte = time.Since(start)
		},
	}
	start = time.Now()

	req, err := http.NewRequestWithContext(
		httptrace.WithClientTrace(ctx, trace),
		http.MethodGet,
		fmt.Sprintf("%v/eth/v1/builder/header/%v/%v/%v", target, nextSlot, blockHash, validatorPubKey),
		nil)
	if err != nil {
		return builderspec.VersionedSignedBuilderBid{}, 0, errors.Wrap(err, "http request")
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return builderspec.VersionedSignedBuilderBid{}, 0, errors.Wrap(err, "http request rtt")
	}
	defer resp.Body.Close()

	// the current proposer was not registered with the builder, wait for next block
	if resp.StatusCode != http.StatusOK {
		return builderspec.VersionedSignedBuilderBid{}, 0, errStatusCodeNot200
	}

	rttGetHeader := firstByte

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return builderspec.VersionedSignedBuilderBid{}, 0, errors.Wrap(err, "http response body")
	}

	var builderBid builderspec.VersionedSignedBuilderBid

	err = json.Unmarshal(bodyBytes, &builderBid)
	if err != nil {
		return builderspec.VersionedSignedBuilderBid{}, 0, errors.Wrap(err, "http response json")
	}

	return builderBid, rttGetHeader, nil
}

func createMEVBlock(ctx context.Context, conf *testMEVConfig, target string, nextSlot int64, latestBlock BeaconBlockMessage, proposerDuties []ProposerDutiesData) (time.Duration, error) {
	var (
		rttGetHeader time.Duration
		builderBid   builderspec.VersionedSignedBuilderBid
	)

	for ctx.Err() == nil {
		startIteration := time.Now()
		epoch := nextSlot / slotsInEpoch

		validatorPubKey, err := getValidatorPKForSlot(proposerDuties, nextSlot)
		if err != nil {
			// if no PK found, refresh the proposerDuties
			proposerDuties, err = fetchProposersForEpoch(ctx, conf, epoch)
			if err != nil {
				return 0, err
			}

			validatorPubKey, err = getValidatorPKForSlot(proposerDuties, nextSlot)
			if err != nil {
				return 0, err
			}
		}

		builderBid, rttGetHeader, err = getBlockHeader(ctx, target, nextSlot, latestBlock.Body.ExecutionPayload.BlockHash, validatorPubKey)
		if err != nil {
			// the current proposer was not registered with the builder, wait for next block
			if errors.Is(err, errStatusCodeNot200) {
				sleepWithContext(ctx, slotTime-time.Since(startIteration)-time.Second)
				startBeaconBlockFetch := time.Now()

				latestBlock, err = latestBeaconBlock(ctx, conf.BeaconNodeEndpoint)
				if err != nil {
					return 0, err
				}

				nextSlot++
				// wait 1 second - the time it took to fetch the latest block
				sleepWithContext(ctx, time.Second-time.Since(startBeaconBlockFetch))

				continue
			}

			return 0, err
		}

		log.Info(ctx, "Created block headers for slot", z.Any("slot", nextSlot), z.Any("target", target))

		break
	}

	// We cannot submit a real block with signature without keys.
	// Use hardcoded signature which we know will fail either way, as a best attempt to fail later in the processing of the BN.
	sig, err := hex.DecodeString("b9251a82040d4620b8c5665f328ee6c2eaa02d31d71d153f4abba31a7922a981e541e85283f0ced387d26e86aef9386d18c6982b9b5f8759882fe7f25a328180d86e146994ef19d28bc1432baf29751dec12b5f3d65dbbe224d72cf900c6831a")
	if err != nil {
		return 0, errors.Wrap(err, "decode signature")
	}

	var payload any

	switch builderBid.Version {
	case eth2spec.DataVersionBellatrix:
		payload = eth2bellatrix.SignedBlindedBeaconBlock{
			Message: &eth2bellatrix.BlindedBeaconBlock{
				Slot:          0,
				ProposerIndex: 0,
				ParentRoot:    eth2p0.Root{},
				StateRoot:     eth2p0.Root{},
				Body: &eth2bellatrix.BlindedBeaconBlockBody{
					RANDAOReveal:           eth2p0.BLSSignature{},
					ETH1Data:               &eth2p0.ETH1Data{},
					Graffiti:               eth2p0.Hash32{},
					ProposerSlashings:      []*eth2p0.ProposerSlashing{},
					AttesterSlashings:      []*eth2p0.AttesterSlashing{},
					Attestations:           []*eth2p0.Attestation{},
					Deposits:               []*eth2p0.Deposit{},
					VoluntaryExits:         []*eth2p0.SignedVoluntaryExit{},
					SyncAggregate:          &eth2a.SyncAggregate{},
					ExecutionPayloadHeader: builderBid.Bellatrix.Message.Header,
				},
			},
			Signature: eth2p0.BLSSignature(sig),
		}
	case eth2spec.DataVersionCapella:
		payload = eth2capella.SignedBlindedBeaconBlock{
			Message: &eth2capella.BlindedBeaconBlock{
				Slot:          0,
				ProposerIndex: 0,
				ParentRoot:    eth2p0.Root{},
				StateRoot:     eth2p0.Root{},
				Body: &eth2capella.BlindedBeaconBlockBody{
					RANDAOReveal:           eth2p0.BLSSignature{},
					ETH1Data:               &eth2p0.ETH1Data{},
					Graffiti:               eth2p0.Hash32{},
					ProposerSlashings:      []*eth2p0.ProposerSlashing{},
					AttesterSlashings:      []*eth2p0.AttesterSlashing{},
					Attestations:           []*eth2p0.Attestation{},
					Deposits:               []*eth2p0.Deposit{},
					VoluntaryExits:         []*eth2p0.SignedVoluntaryExit{},
					SyncAggregate:          &eth2a.SyncAggregate{},
					ExecutionPayloadHeader: builderBid.Capella.Message.Header,
				},
			},
			Signature: eth2p0.BLSSignature(sig),
		}
	case eth2spec.DataVersionDeneb:
		payload = eth2deneb.SignedBlindedBeaconBlock{
			Message: &eth2deneb.BlindedBeaconBlock{
				Slot:          0,
				ProposerIndex: 0,
				ParentRoot:    eth2p0.Root{},
				StateRoot:     eth2p0.Root{},
				Body: &eth2deneb.BlindedBeaconBlockBody{
					RANDAOReveal:           eth2p0.BLSSignature{},
					ETH1Data:               &eth2p0.ETH1Data{},
					Graffiti:               eth2p0.Hash32{},
					ProposerSlashings:      []*eth2p0.ProposerSlashing{},
					AttesterSlashings:      []*eth2p0.AttesterSlashing{},
					Attestations:           []*eth2p0.Attestation{},
					Deposits:               []*eth2p0.Deposit{},
					VoluntaryExits:         []*eth2p0.SignedVoluntaryExit{},
					SyncAggregate:          &eth2a.SyncAggregate{},
					ExecutionPayloadHeader: builderBid.Deneb.Message.Header,
				},
			},
			Signature: eth2p0.BLSSignature(sig),
		}
	case eth2spec.DataVersionElectra, eth2spec.DataVersionFulu: // same block structure for both
		payload = eth2electra.SignedBlindedBeaconBlock{
			Message: &eth2electra.BlindedBeaconBlock{
				Slot:          0,
				ProposerIndex: 0,
				ParentRoot:    eth2p0.Root{},
				StateRoot:     eth2p0.Root{},
				Body: &eth2electra.BlindedBeaconBlockBody{
					RANDAOReveal:           eth2p0.BLSSignature{},
					ETH1Data:               &eth2p0.ETH1Data{},
					Graffiti:               eth2p0.Hash32{},
					ProposerSlashings:      []*eth2p0.ProposerSlashing{},
					AttesterSlashings:      []*eth2e.AttesterSlashing{},
					Attestations:           []*eth2e.Attestation{},
					Deposits:               []*eth2p0.Deposit{},
					VoluntaryExits:         []*eth2p0.SignedVoluntaryExit{},
					SyncAggregate:          &eth2a.SyncAggregate{},
					ExecutionPayloadHeader: builderBid.Electra.Message.Header,
				},
			},
			Signature: eth2p0.BLSSignature(sig),
		}
	default:
		return 0, errors.New("not supported version", z.Str("version", builderBid.Version.String()))
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return 0, errors.Wrap(err, "signed blinded beacon block json payload marshal")
	}

	rttSubmitBlock, err := requestRTT(ctx, target+"/eth/v1/builder/blinded_blocks", http.MethodPost, bytes.NewReader(payloadJSON), 400)
	if err != nil {
		return 0, err
	}

	return rttGetHeader + rttSubmitBlock, nil
}

type BeaconBlock struct {
	Data BeaconBlockData `json:"data"`
}

type BeaconBlockData struct {
	Message BeaconBlockMessage `json:"message"`
}

type BeaconBlockMessage struct {
	Slot string          `json:"slot"`
	Body BeaconBlockBody `json:"body"`
}

type BeaconBlockBody struct {
	ExecutionPayload BeaconBlockExecPayload `json:"execution_payload"`
}

type BeaconBlockExecPayload struct {
	BlockHash string `json:"block_hash"`
	Timestamp string `json:"timestamp"`
}

func latestBeaconBlock(ctx context.Context, endpoint string) (BeaconBlockMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%v/eth/v2/beacon/blocks/head", endpoint), nil)
	if err != nil {
		return BeaconBlockMessage{}, errors.Wrap(err, "http request")
	}

	resp, err := new(http.Client).Do(req)
	if err != nil {
		return BeaconBlockMessage{}, errors.Wrap(err, "http request do")
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return BeaconBlockMessage{}, errors.Wrap(err, "http response body")
	}

	var beaconBlock BeaconBlock

	err = json.Unmarshal(bodyBytes, &beaconBlock)
	if err != nil {
		return BeaconBlockMessage{}, errors.Wrap(err, "http response json")
	}

	return beaconBlock.Data.Message, nil
}

type ProposerDuties struct {
	Data []ProposerDutiesData `json:"data"`
}

type ProposerDutiesData struct {
	PubKey string `json:"pubkey"`
	Slot   string `json:"slot"`
}

func fetchProposersForEpoch(ctx context.Context, conf *testMEVConfig, epoch int64) ([]ProposerDutiesData, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%v/eth/v1/validator/duties/proposer/%v", conf.BeaconNodeEndpoint, epoch), nil)
	if err != nil {
		return nil, errors.Wrap(err, "http request")
	}

	resp, err := new(http.Client).Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "http request do")
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "http response body")
	}

	var proposerDuties ProposerDuties

	err = json.Unmarshal(bodyBytes, &proposerDuties)
	if err != nil {
		return nil, errors.Wrap(err, "http response json")
	}

	return proposerDuties.Data, nil
}

func getValidatorPKForSlot(proposers []ProposerDutiesData, slot int64) (string, error) {
	slotString := strconv.FormatInt(slot, 10)
	for _, s := range proposers {
		if s.Slot == slotString {
			return s.PubKey, nil
		}
	}

	return "", errors.New("slot not found")
}
