// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

type testBeaconConfig struct {
	testConfig
	Endpoints            []string
	EnableLoadTest       bool
	LoadTestDuration     time.Duration
	EnableSimulation     bool
	SimulationValidators int
	SimulationFileDir    string
	SimulationDuration   int
}

type testCaseBeacon func(context.Context, *testBeaconConfig, string) testResult

type SimulationValues struct {
	Min    Duration
	Max    Duration
	Median Duration
	Avg    Duration
}

type RequestsIntensity struct {
	AttestationDuty     time.Duration
	AggregatorDuty      time.Duration
	SyncCommitteeDuties time.Duration
	ProposalDuty        time.Duration
}

type Simulation struct {
	GeneralRequests SimulationGeneralRequests
	Validators      []SimulationPerValidator
}

type SimulationPerValidator struct {
	Attestation SimulationAttestation
	Aggregation SimulationAggregation
	Proposal    SimulationProposal
}

type SimulationAttestation struct {
	AttestationGetDuties SimulationValues
	AttestationPostData  SimulationValues
	SimulationValues
}

type SimulationAggregation struct {
	AggregationGetAggregationAttestations SimulationValues
	AggregationSubmitAggregateAndProofs   SimulationValues
	SimulationValues
}

type SimulationProposal struct {
	ProposalProduceBlock        SimulationValues
	ProposalPublishBlindedBlock SimulationValues
	SimulationValues
}

type SimulationGeneralRequests struct {
	AttestationsForBlock   SimulationValues
	ProposalDutiesForEpoch SimulationValues
	Syncing                SimulationValues
}

const (
	thresholdBeaconMeasureAvg  = 40 * time.Millisecond
	thresholdBeaconMeasurePoor = 100 * time.Millisecond
	thresholdBeaconLoadAvg     = 40 * time.Millisecond
	thresholdBeaconLoadPoor    = 100 * time.Millisecond
	thresholdBeaconPeersAvg    = 50
	thresholdBeaconPeersPoor   = 20

	thresholdBeaconSimulationAvg  = 200 * time.Millisecond
	thresholdBeaconSimulationPoor = 400 * time.Millisecond
	committeeIndexSizePerSlot     = 64
	slotTime                      = 12 * time.Second
	slotsInEpoch                  = 32
	epochTime                     = slotsInEpoch * slotTime
)

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
	cmd.Flags().BoolVar(&config.EnableLoadTest, "enable-load-test", false, "Enable load test, not advisable when testing towards external beacon nodes.")
	cmd.Flags().DurationVar(&config.LoadTestDuration, "load-test-duration", 5*time.Second, "Time to keep running the load tests in seconds. For each second a new continuous ping instance is spawned.")
	cmd.Flags().BoolVar(&config.EnableSimulation, "enable-simulation", false, "Enable simulation test, not advisable when testing towards external beacon nodes.")
	cmd.Flags().StringVar(&config.SimulationFileDir, "simulation-file-dir", "./", "JSON directory to which simulation file results will be written.")
	cmd.Flags().IntVar(&config.SimulationDuration, "simulation-duration-in-slots", slotsInEpoch, "Time to keep running the simulation in slots.")
}

func supportedBeaconTestCases() map[testCaseName]testCaseBeacon {
	return map[testCaseName]testCaseBeacon{
		{name: "ping", order: 1}:        beaconPingTest,
		{name: "pingMeasure", order: 2}: beaconPingMeasureTest,
		{name: "isSynced", order: 3}:    beaconIsSyncedTest,
		{name: "peerCount", order: 4}:   beaconPeerCountTest,
		{name: "pingLoad", order: 5}:    beaconPingLoadTest,

		{name: "simulate10", order: 6}: beaconSimulation10Test,
	}
}

func runTestBeacon(ctx context.Context, w io.Writer, cfg testBeaconConfig) (err error) {
	testCases := supportedBeaconTestCases()
	queuedTests := filterTests(maps.Keys(testCases), cfg.testConfig)
	if len(queuedTests) == 0 {
		return errors.New("test case not supported")
	}
	sortTests(queuedTests)

	timeoutCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	testResultsChan := make(chan map[string][]testResult)
	testResults := make(map[string][]testResult)
	startTime := time.Now()

	// run test suite for all beacon nodes
	go testAllBeacons(timeoutCtx, queuedTests, testCases, cfg, testResultsChan)

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

	res := testCategoryResult{
		CategoryName:  beaconTestCategory,
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

func testAllBeacons(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]testCaseBeacon, conf testBeaconConfig, allBeaconsResCh chan map[string][]testResult) {
	defer close(allBeaconsResCh)
	// run tests for all beacon nodes
	allBeaconsRes := make(map[string][]testResult)
	singleBeaconResCh := make(chan map[string][]testResult)
	group, _ := errgroup.WithContext(ctx)

	for _, endpoint := range conf.Endpoints {
		currEndpoint := endpoint // TODO: can be removed after go1.22 version bump
		group.Go(func() error {
			return testSingleBeacon(ctx, queuedTestCases, allTestCases, conf, currEndpoint, singleBeaconResCh)
		})
	}

	doneReading := make(chan bool)
	go func() {
		for singleBeaconRes := range singleBeaconResCh {
			maps.Copy(allBeaconsRes, singleBeaconRes)
		}
		doneReading <- true
	}()

	err := group.Wait()
	if err != nil {
		return
	}
	close(singleBeaconResCh)
	<-doneReading

	allBeaconsResCh <- allBeaconsRes
}

func testSingleBeacon(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]testCaseBeacon, cfg testBeaconConfig, target string, resCh chan map[string][]testResult) error {
	singleTestResCh := make(chan testResult)
	allTestRes := []testResult{}

	// run all beacon tests for a beacon node, pushing each completed test to the channel until all are complete or timeout occurs
	go runBeaconTest(ctx, queuedTestCases, allTestCases, cfg, target, singleTestResCh)
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
			testName = queuedTestCases[testCounter].name
			testCounter++
			result.Name = testName
			allTestRes = append(allTestRes, result)
		}
	}

	resCh <- map[string][]testResult{target: allTestRes}

	return nil
}

func runBeaconTest(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]testCaseBeacon, cfg testBeaconConfig, target string, ch chan testResult) {
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

func beaconPingTest(ctx context.Context, _ *testBeaconConfig, target string) testResult {
	testRes := testResult{Name: "Ping"}

	client := http.Client{}
	targetEndpoint := fmt.Sprintf("%v/eth/v1/node/health", target)
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
		return failedTestResult(testRes, errors.New("status code %v", z.Int("status_code", resp.StatusCode)))
	}

	testRes.Verdict = testVerdictOk

	return testRes
}

func beaconPingOnce(ctx context.Context, target string) (time.Duration, error) {
	var start time.Time
	var firstByte time.Duration

	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			firstByte = time.Since(start)
		},
	}

	start = time.Now()
	targetEndpoint := fmt.Sprintf("%v/eth/v1/node/health", target)
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, targetEndpoint, nil)
	if err != nil {
		return 0, errors.Wrap(err, "create new request with trace and context")
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode > 399 {
		return 0, errors.New("status code %v", z.Int("status_code", resp.StatusCode))
	}

	return firstByte, nil
}

func beaconPingMeasureTest(ctx context.Context, _ *testBeaconConfig, target string) testResult {
	testRes := testResult{Name: "PingMeasure"}

	rtt, err := beaconPingOnce(ctx, target)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	if rtt > thresholdBeaconMeasurePoor {
		testRes.Verdict = testVerdictPoor
	} else if rtt > thresholdBeaconMeasureAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = Duration{rtt}.String()

	return testRes
}

func pingBeaconContinuously(ctx context.Context, target string, resCh chan<- time.Duration) {
	for {
		rtt, err := beaconPingOnce(ctx, target)
		if err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case resCh <- rtt:
			awaitTime := rand.Intn(100) //nolint:gosec // weak generator is not an issue here
			sleepWithContext(ctx, time.Duration(awaitTime)*time.Millisecond)
		}
	}
}

func beaconPingLoadTest(ctx context.Context, conf *testBeaconConfig, target string) testResult {
	testRes := testResult{Name: "BeaconLoad"}
	if !conf.EnableLoadTest {
		testRes.Verdict = testVerdictSkipped
		return testRes
	}
	log.Info(ctx, "Running ping load tests...",
		z.Any("duration", conf.LoadTestDuration),
		z.Any("target", target),
	)

	testResCh := make(chan time.Duration, math.MaxInt16)
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
				pingBeaconContinuously(pingCtx, target, testResCh)
				wg.Done()
			}()
		case <-pingCtx.Done():
		}
	}
	wg.Wait()
	close(testResCh)
	log.Info(ctx, "Ping load tests finished", z.Any("target", target))

	highestRTT := time.Duration(0)
	for rtt := range testResCh {
		if rtt > highestRTT {
			highestRTT = rtt
		}
	}
	if highestRTT > thresholdBeaconLoadPoor {
		testRes.Verdict = testVerdictPoor
	} else if highestRTT > thresholdBeaconLoadAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = Duration{highestRTT}.String()

	return testRes
}

func beaconIsSyncedTest(ctx context.Context, _ *testBeaconConfig, target string) testResult {
	testRes := testResult{Name: "isSynced"}

	type isSyncedResponse struct {
		Data eth2v1.SyncState `json:"data"`
	}

	client := http.Client{}
	targetEndpoint := fmt.Sprintf("%v/eth/v1/node/syncing", target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetEndpoint, nil)
	if err != nil {
		return failedTestResult(testRes, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	if resp.StatusCode > 399 {
		return failedTestResult(testRes, errors.New("status code %v", z.Int("status_code", resp.StatusCode)))
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return failedTestResult(testRes, err)
	}
	defer resp.Body.Close()

	var respUnmarshaled isSyncedResponse
	err = json.Unmarshal(b, &respUnmarshaled)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	if respUnmarshaled.Data.IsSyncing {
		testRes.Verdict = testVerdictFail
		return testRes
	}

	testRes.Verdict = testVerdictOk

	return testRes
}

func beaconPeerCountTest(ctx context.Context, _ *testBeaconConfig, target string) testResult {
	testRes := testResult{Name: "peerCount"}

	type peerCountResponseMeta struct {
		Count int `json:"count"`
	}

	type peerCountResponse struct {
		Meta peerCountResponseMeta `json:"meta"`
	}

	client := http.Client{}
	targetEndpoint := fmt.Sprintf("%v/eth/v1/node/peers?state=connected", target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetEndpoint, nil)
	if err != nil {
		return failedTestResult(testRes, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	if resp.StatusCode > 399 {
		return failedTestResult(testRes, errors.New("status code %v", z.Int("status_code", resp.StatusCode)))
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return failedTestResult(testRes, err)
	}
	defer resp.Body.Close()

	var respUnmarshaled peerCountResponse
	err = json.Unmarshal(b, &respUnmarshaled)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	testRes.Measurement = strconv.Itoa(respUnmarshaled.Meta.Count)

	if respUnmarshaled.Meta.Count < thresholdBeaconPeersPoor {
		testRes.Verdict = testVerdictPoor
	} else if respUnmarshaled.Meta.Count < thresholdBeaconPeersAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}

	return testRes
}

func beaconSimulation10Test(ctx context.Context, conf *testBeaconConfig, target string) testResult {
	testRes := testResult{Name: "BeaconSimulation10Validators"}
	if !conf.EnableSimulation {
		testRes.Verdict = testVerdictSkipped
		return testRes
	}
	validatorsCount := 10

	log.Info(ctx, "Running simulation for 10 validators tests...",
		z.Any("validators", validatorsCount),
		z.Any("target", target),
		z.Any("duration_in_slots", conf.SimulationDuration),
		z.Any("slot_duration", slotTime),
	)

	intensity := RequestsIntensity{
		AttestationDuty:     slotTime,
		AggregatorDuty:      slotTime * 2,
		ProposalDuty:        slotTime * 4,
		SyncCommitteeDuties: epochTime,
	}

	duration := time.Duration(conf.SimulationDuration)*slotTime + time.Second

	simulationGeneralResCh := make(chan SimulationGeneralRequests)
	simulationGeneralRes := SimulationGeneralRequests{}
	go singleClusterSimulation(ctx, duration, target, simulationGeneralResCh)
	simulationResCh := make(chan SimulationPerValidator)
	simulationResAll := []SimulationPerValidator{}
	for v := range validatorsCount {
		valCtx := log.WithCtx(ctx, z.Int("validator", v))
		go singleValidatorSimulation(valCtx, duration, target, simulationResCh, intensity)
	}

	finished := false
	for !finished {
		select {
		case <-ctx.Done():
			finished = true
			continue
		case result, ok := <-simulationResCh:
			if !ok {
				finished = true
				continue
			}
			simulationResAll = append(simulationResAll, result)
			if len(simulationResAll) == validatorsCount {
				finished = true
			}
		}
	}
	close(simulationResCh)

	select {
	case <-ctx.Done():
	case result, ok := <-simulationGeneralResCh:
		if !ok {
			log.Error(ctx, "Failed to get result from simulationGeneralResCh", errors.New("not ok"))
			break
		}
		simulationGeneralRes = result
	}
	close(simulationGeneralResCh)

	finalSimulation := Simulation{
		GeneralRequests: simulationGeneralRes,
		Validators:      simulationResAll,
	}
	simulationResAllJSON, err := json.Marshal(finalSimulation)
	if err != nil {
		log.Error(ctx, "Failed to marshal simulation result", err)
	}
	err = os.WriteFile(filepath.Join(conf.SimulationFileDir, "10-validators.json"), simulationResAllJSON, 0o644) //nolint:gosec
	if err != nil {
		log.Error(ctx, "Failed to write file", err)
	}

	highestRTT := Duration{0}
	for _, sim := range simulationResAll {
		simulationMax := Duration{max(sim.Attestation.Max.Duration)}
		if simulationMax.Duration > highestRTT.Duration {
			highestRTT = simulationMax
		}
	}
	if highestRTT.Duration > thresholdBeaconSimulationPoor {
		testRes.Verdict = testVerdictPoor
	} else if highestRTT.Duration > thresholdBeaconSimulationAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = highestRTT.String()

	return testRes
}

func getCurrentSlot(ctx context.Context, target string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target+"/eth/v1/node/syncing", nil)
	if err != nil {
		return 0, errors.Wrap(err, "create new http request")
	}
	resp, err := new(http.Client).Do(req)
	if err != nil {
		return 0, errors.Wrap(err, "call /eth/v1/node/syncing endpoint")
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return 0, errors.New("post failed", z.Int("status", resp.StatusCode))
	}

	type syncingResponseData struct {
		HeadSlot string `json:"head_slot"`
	}
	type syncingResponse struct {
		Data syncingResponseData `json:"data"`
	}
	var sr syncingResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return 0, errors.Wrap(err, "json unmarshal error")
	}

	head, err := strconv.Atoi(sr.Data.HeadSlot)
	if err != nil {
		return 0, errors.Wrap(err, "head slot string to int")
	}

	return head, nil
}

func singleClusterSimulation(ctx context.Context, simulationDuration time.Duration, target string, resultCh chan SimulationGeneralRequests) {
	// per slot requests
	attestationsForBlockCh := make(chan time.Duration)
	attestationsForBlockAll := []time.Duration{}
	proposalDutiesForEpochCh := make(chan time.Duration)
	proposalDutiesForEpochAll := []time.Duration{}
	syncingCh := make(chan time.Duration)
	syncingAll := []time.Duration{}
	log.Info(ctx, "Starting general cluster requests...")
	slot, err := getCurrentSlot(ctx, target)
	if err != nil {
		log.Error(ctx, "Failed to get current slot", err)
		slot = 1
	}
	go clusterGeneralRequests(ctx, target, slot, slotTime, simulationDuration, attestationsForBlockCh, proposalDutiesForEpochCh, syncingCh)

	finished := false
	for !finished {
		select {
		case <-ctx.Done():
			finished = true
		case result, ok := <-attestationsForBlockCh:
			if !ok {
				finished = true
				continue
			}
			attestationsForBlockAll = append(attestationsForBlockAll, result)
		case result, ok := <-proposalDutiesForEpochCh:
			if !ok {
				finished = true
				continue
			}
			proposalDutiesForEpochAll = append(proposalDutiesForEpochAll, result)
		case result, ok := <-syncingCh:
			if !ok {
				finished = true
				continue
			}
			syncingAll = append(syncingAll, result)
		}
	}

	attestationsForBlockValues := simulationValuesFromSlice(attestationsForBlockAll)
	proposalDutiesForEpochValues := simulationValuesFromSlice(proposalDutiesForEpochAll)
	syncingValues := simulationValuesFromSlice(syncingAll)

	generalResults := SimulationGeneralRequests{
		AttestationsForBlock:   attestationsForBlockValues,
		ProposalDutiesForEpoch: proposalDutiesForEpochValues,
		Syncing:                syncingValues,
	}

	log.Info(ctx, "General requests simulation for cluster finished")
	resultCh <- generalResults
}

func clusterGeneralRequests(ctx context.Context, target string, slot int, slotTime time.Duration, simulationDuration time.Duration, attestationsForBlockCh chan time.Duration, proposalDutiesForEpochCh chan time.Duration, syncingCh chan time.Duration) {
	defer func() {
		close(proposalDutiesForEpochCh)
		close(attestationsForBlockCh)
		close(syncingCh)
	}()
	pingCtx, cancel := context.WithTimeout(ctx, simulationDuration)
	defer cancel()
	tickerPerSlot := time.NewTicker(slotTime)
	defer tickerPerSlot.Stop()
	tickerPer10Sec := time.NewTicker(10 * time.Second)
	defer tickerPer10Sec.Stop()
	for pingCtx.Err() == nil {
		select {
		case <-tickerPerSlot.C:
			attestationsResult, err := getAttestationsForBlock(ctx, target, slot-6)
			if err != nil {
				log.Error(ctx, "Unexpected getAttestationsForBlock failure", err)
			}
			submitResult, err := getProposalDutiesForEpoch(ctx, target, slot/slotsInEpoch)
			if err != nil {
				log.Error(ctx, "Unexpected getProposalDutiesForEpoch failure", err)
			}
			attestationsForBlockCh <- attestationsResult
			proposalDutiesForEpochCh <- submitResult
			slot++
		case <-tickerPer10Sec.C:
			getSyncingResult, err := getSyncing(ctx, target)
			if err != nil {
				log.Error(ctx, "Unexpected getSyncing failure", err)
			}
			syncingCh <- getSyncingResult
		case <-pingCtx.Done():
		}
	}
}

func singleValidatorSimulation(ctx context.Context, simulationDuration time.Duration, target string, resultCh chan SimulationPerValidator, intensity RequestsIntensity) {
	slot, err := getCurrentSlot(ctx, target)
	if err != nil {
		log.Error(ctx, "Failed to get current slot", err)
		slot = 1
	}

	// attestations
	getAttestationDataCh := make(chan time.Duration)
	getAttestationDataAll := []time.Duration{}
	submitAttestationObjectCh := make(chan time.Duration)
	submitAttestationObjectAll := []time.Duration{}
	log.Info(ctx, "Starting attestation duties...")
	go attestationDuty(ctx, target, slot, simulationDuration, intensity.AttestationDuty, getAttestationDataCh, submitAttestationObjectCh)

	// aggregations
	getAggregateAttestationsCh := make(chan time.Duration)
	getAggregateAttestationsAll := []time.Duration{}
	submitAggregateAndProofsCh := make(chan time.Duration)
	submitAggregateAndProofsAll := []time.Duration{}
	log.Info(ctx, "Starting aggregation duties...")
	go aggregationDuty(ctx, target, slot, simulationDuration, intensity.AggregatorDuty, getAggregateAttestationsCh, submitAggregateAndProofsCh)

	// proposals
	produceBlockCh := make(chan time.Duration)
	produceBlockAll := []time.Duration{}
	publishBlindedBlockCh := make(chan time.Duration)
	publishBlindedBlockAll := []time.Duration{}
	log.Info(ctx, "Starting proposal duties...")
	go proposalDuty(ctx, target, slot, simulationDuration, intensity.ProposalDuty, produceBlockCh, publishBlindedBlockCh)

	// capture results
	finished := false
	for !finished {
		select {
		case <-ctx.Done():
			finished = true
		case result, ok := <-getAttestationDataCh:
			if !ok {
				finished = true
				continue
			}
			getAttestationDataAll = append(getAttestationDataAll, result)
		case result, ok := <-submitAttestationObjectCh:
			if !ok {
				finished = true
				continue
			}
			submitAttestationObjectAll = append(submitAttestationObjectAll, result)
		case result, ok := <-getAggregateAttestationsCh:
			if !ok {
				finished = true
				continue
			}
			getAggregateAttestationsAll = append(getAggregateAttestationsAll, result)
		case result, ok := <-submitAggregateAndProofsCh:
			if !ok {
				finished = true
				continue
			}
			submitAggregateAndProofsAll = append(submitAggregateAndProofsAll, result)
		case result, ok := <-produceBlockCh:
			if !ok {
				finished = true
				continue
			}
			produceBlockAll = append(produceBlockAll, result)
		case result, ok := <-publishBlindedBlockCh:
			if !ok {
				finished = true
				continue
			}
			publishBlindedBlockAll = append(publishBlindedBlockAll, result)
		}
	}

	// attestation results grouping
	getSimulationValues := simulationValuesFromSlice(getAttestationDataAll)
	submitSimulationValues := simulationValuesFromSlice(submitAttestationObjectAll)

	cumulativeAttestation := []time.Duration{}
	for i := range getAttestationDataAll {
		cumulativeAttestation = append(cumulativeAttestation, getAttestationDataAll[i]+submitAttestationObjectAll[i])
	}
	cumulativeSimulationValues := simulationValuesFromSlice(cumulativeAttestation)

	attestationResult := SimulationAttestation{
		AttestationGetDuties: getSimulationValues,
		AttestationPostData:  submitSimulationValues,
		SimulationValues:     cumulativeSimulationValues,
	}

	// aggregation results grouping
	getAggregateSimulationValues := simulationValuesFromSlice(getAggregateAttestationsAll)
	submitAggregateSimulationValues := simulationValuesFromSlice(submitAggregateAndProofsAll)

	cumulativeAggregations := []time.Duration{}
	for i := range getAggregateAttestationsAll {
		cumulativeAggregations = append(cumulativeAggregations, getAggregateAttestationsAll[i]+submitAggregateAndProofsAll[i])
	}
	cumulativeAggregationsSimulationValues := simulationValuesFromSlice(cumulativeAggregations)

	aggregationResults := SimulationAggregation{
		AggregationGetAggregationAttestations: getAggregateSimulationValues,
		AggregationSubmitAggregateAndProofs:   submitAggregateSimulationValues,
		SimulationValues:                      cumulativeAggregationsSimulationValues,
	}

	// proposal results grouping
	produceBlockValues := simulationValuesFromSlice(produceBlockAll)
	publishBlindedBlockValues := simulationValuesFromSlice(publishBlindedBlockAll)

	cumulativeProposals := []time.Duration{}
	for i := range produceBlockAll {
		cumulativeProposals = append(cumulativeProposals, produceBlockAll[i]+publishBlindedBlockAll[i])
	}
	cumulativeProposalsSimulationValues := simulationValuesFromSlice(cumulativeProposals)

	proposalResults := SimulationProposal{
		ProposalProduceBlock:        produceBlockValues,
		ProposalPublishBlindedBlock: publishBlindedBlockValues,
		SimulationValues:            cumulativeProposalsSimulationValues,
	}

	log.Info(ctx, "Simulation for validator finished")
	resultCh <- SimulationPerValidator{
		Attestation: attestationResult,
		Aggregation: aggregationResults,
		Proposal:    proposalResults,
	}
}

func simulationValuesFromSlice(s []time.Duration) SimulationValues {
	sort.Slice(s, func(i, j int) bool {
		return s[i] < s[j]
	})
	minVal := s[0]
	maxVal := s[len(s)-1]
	medianVal := s[len(s)/2]
	var all time.Duration
	for _, t := range s {
		all += t
	}
	avgVal := time.Duration(int(all.Nanoseconds()) / len(s))

	return SimulationValues{
		Min:    Duration{minVal},
		Max:    Duration{maxVal},
		Median: Duration{medianVal},
		Avg:    Duration{avgVal},
	}
}

func aggregationDuty(ctx context.Context, target string, slot int, simulationDuration time.Duration, tickTime time.Duration, getAggregateAttestationsCh chan time.Duration, submitAggregateAndProofsCh chan time.Duration) {
	defer close(getAggregateAttestationsCh)
	defer close(submitAggregateAndProofsCh)
	pingCtx, cancel := context.WithTimeout(ctx, simulationDuration)
	defer cancel()
	ticker := time.NewTicker(tickTime)
	defer ticker.Stop()
	for pingCtx.Err() == nil {
		select {
		case <-ticker.C:
			// TODO: use real attestation data root
			getResult, err := getAggregateAttestations(ctx, target, slot, "0x87db5c50a4586fa37662cf332382d56a0eeea688a7d7311a42735683dfdcbfa4")
			if err != nil {
				log.Error(ctx, "Unexpected getAggregateAttestations failure", err)
			}
			submitResult, err := aggregateAndProofs(ctx, target)
			if err != nil {
				log.Error(ctx, "Unexpected aggregateAndProofs failure", err)
			}
			getAggregateAttestationsCh <- getResult
			submitAggregateAndProofsCh <- submitResult
			slot += int(tickTime.Seconds()) / int(slotTime.Seconds())
		case <-pingCtx.Done():
		}
	}
	log.Info(ctx, "Aggregation duty simulation finished")
}

func proposalDuty(ctx context.Context, target string, slot int, simulationDuration time.Duration, tickTime time.Duration, produceBlockCh chan time.Duration, publishBlindedBlockCh chan time.Duration) {
	defer close(produceBlockCh)
	defer close(publishBlindedBlockCh)
	pingCtx, cancel := context.WithTimeout(ctx, simulationDuration)
	defer cancel()
	ticker := time.NewTicker(tickTime)
	defer ticker.Stop()
	for pingCtx.Err() == nil {
		select {
		case <-ticker.C:
			produceResult, err := produceBlock(ctx, target, slot, "0x9880dad5a0e900906a1355da0697821af687b4c2cd861cd219f2d779c50a47d3c0335c08d840c86c167986ae0aaf50070b708fe93a83f66c99a4f931f9a520aebb0f5b11ca202c3d76343e30e49f43c0479e850af0e410333f7c")
			if err != nil {
				log.Error(ctx, "Unexpected getAggregateAttestations failure", err)
			}
			publishResult, err := publishBlindedBlock(ctx, target)
			if err != nil {
				log.Error(ctx, "Unexpected aggregateAndProofs failure", err)
			}
			produceBlockCh <- produceResult
			publishBlindedBlockCh <- publishResult
			slot += int(tickTime.Seconds()) / int(slotTime.Seconds())
		case <-pingCtx.Done():
		}
	}
	log.Info(ctx, "Proposal duty simulation finished")
}

func attestationDuty(ctx context.Context, target string, slot int, simulationDuration time.Duration, tickTime time.Duration, getAttestationDataCh chan time.Duration, submitAttestationObjectCh chan time.Duration) {
	defer close(getAttestationDataCh)
	defer close(submitAttestationObjectCh)
	pingCtx, cancel := context.WithTimeout(ctx, simulationDuration)
	defer cancel()
	ticker := time.NewTicker(tickTime)
	defer ticker.Stop()
	for pingCtx.Err() == nil {
		select {
		case <-ticker.C:
			getResult, err := getAttestationData(ctx, target, slot, rand.Intn(committeeIndexSizePerSlot)) //nolint:gosec // weak generator is not an issue here
			if err != nil {
				log.Error(ctx, "Unexpected getAttestationData failure", err)
			}
			submitResult, err := submitAttestationObject(ctx, target)
			if err != nil {
				log.Error(ctx, "Unexpected submitAttestationObject failure", err)
			}
			getAttestationDataCh <- getResult
			submitAttestationObjectCh <- submitResult
			slot += int(tickTime.Seconds()) / int(slotTime.Seconds())
		case <-pingCtx.Done():
		}
	}
	log.Info(ctx, "Attestation duty simulation finished")
}

func requestRTT(ctx context.Context, url string, method string, body io.Reader, isOK bool) (time.Duration, error) {
	var start time.Time
	var firstByte time.Duration

	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			firstByte = time.Since(start)
		},
	}

	start = time.Now()
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), method, url, body)
	if err != nil {
		return 0, errors.Wrap(err, "create new request with trace and context")
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if isOK {
		if resp.StatusCode > 399 {
			data, err := io.ReadAll(resp.Body)
			if err != nil {
				return 0, errors.New("http GET failed", z.Int("status_code", resp.StatusCode), z.Str("endpoint", url))
			}

			return 0, errors.New("http GET failed", z.Int("status_code", resp.StatusCode), z.Str("endpoint", url), z.Str("body", string(data)))
		}
	}

	return firstByte, nil
}

func produceBlock(ctx context.Context, target string, slot int, randaoReveal string) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v3/validator/blocks/%v?randao_reveal=%v", target, slot, randaoReveal), http.MethodGet, nil, true)
}

func publishBlindedBlock(ctx context.Context, target string) (time.Duration, error) {
	body := strings.NewReader(`{"message":{"slot":"2872079","proposer_index":"1725813","parent_root":"0x05bea9b8e9cc28c4efa5586b4efac20b7a42c3112dbe144fb552b37ded249abd","state_root":"0x0138e6e8e956218aa534597a450a93c2c98f07da207077b4be05742279688da2","body":{"randao_reveal":"0x9880dad5a0e900906a1355da0697821af687b4c2cd861cd219f2d779c50a47d3c0335c08d840c86c167986ae0aaf50070b708fe93a83f66c99a4f931f9a520aebb0f5b11ca202c3d76343e30e49f43c0479e850af0e410333f7c59c4d37fa95a","eth1_data":{"deposit_root":"0x7dbea1a0af14d774da92d94a88d3bb1ae7abad16374da4db2c71dd086c84029e","deposit_count":"452100","block_hash":"0xc4bf450c9e362dcb2b50e76b45938c78d455acd1e1aec4e1ce4338ec023cd32a"},"graffiti":"0x636861726f6e2f76312e312e302d613139336638340000000000000000000000","proposer_slashings":[],"attester_slashings":[],"attestations":[{"aggregation_bits":"0xdbedbfa74eccaf3d7ef570bfdbbf84b4dffc5beede1c1f8b59feb8b3f2fbabdbdef3ceeb7b3dfdeeef8efcbdcd7bebbeff7adfff5ae3bf66bc5613feffef3deb987f7e7fff87ed6f8bbd1fffa57f1677efff646f0d3bd79fffdc5dfd78df6cf79fb7febff5dfdefb8e03","data":{"slot":"2872060","index":"12","beacon_block_root":"0x310506169f7f92dcd2bf00e8b4c2daac999566929395120fbbf4edd222e003eb","source":{"epoch":"89750","root":"0xcdb449d69e3e2d22378bfc2299ee1e9aeb1b2d15066022e854759dda73d1e219"},"target":{"epoch":"89751","root":"0x4ad0882f7adbb735c56b0b3f09d8e45dbd79db9528110f7117ec067f3a19eb0e"}},"signature":"0xa9d91d6cbc669ffcc8ba2435c633e0ec0eebecaa3acdcaa1454282ece1f816e8b853f00ba67ec1244703221efae4c834012819ca7b199354669f24ba8ab1c769f072c9f46b803082eac32e3611cd323eeb5b17fcd6201b41f3063834ff26ef53"}],"deposits":[],"voluntary_exits":[],"sync_aggregate":{"sync_committee_bits":"0xf9ff3ff7ffffb7dbfefddff5fffffefdbffffffffffedfefffffff7fbe9fdffffdb5feffffffbfdbefff3ffdf7f3fc6ff7fffbffff9df6fbbaf3beffefffffff","sync_committee_signature":"0xa9cf7d9f23a62e84f11851e2e4b3b929b1d03719a780b59ecba5daf57e21a0ceccaf13db4e1392a42e3603abeb839a2d16373dcdd5e696f11c5a809972c1e368d794f1c61d4d10b220df52616032f09b33912febf8c7a64f3ce067ab771c7ddf"},"execution_payload_header":{"parent_hash":"0x71c564f4a0c1dea921e8063fc620ccfa39c1b073e4ac0845ce7e9e6f909752de","fee_recipient":"0x148914866080716b10D686F5570631Fbb2207002","state_root":"0x89e74be562cd4a10eb20cdf674f65b1b0e53b33a7c3f2df848eb4f7e226742e0","receipts_root":"0x55b494ee1bb919e7abffaab1d5be05a109612c59a77406d929d77c0ce714f21d","logs_bloom":"0x20500886140245d001002010680c10411a2540420182810440a108800fc008440801180020011008004045005a2007826802e102000005c0c04030590004044810d0d20745c0904a4d583008a01758018001082024e40046000410020042400100012260220299a8084415e20002891224c132220010003a00006010020ed0c108920a13c0e200a1a00251100888c01408008132414068c88b028920440248209a280581a0e10800c14ea63082c1781308208b130508d4000400802d1224521094260912473404012810001503417b4050141100c1103004000c8900644560080472688450710084088800c4c80000c02008931188204c008009011784488060","prev_randao":"0xf4e9a4a7b88a3d349d779e13118b6d099f7773ec5323921343ac212df19c620f","block_number":"2643688","gas_limit":"30000000","gas_used":"24445884","timestamp":"1730367348","extra_data":"0x546974616e2028746974616e6275696c6465722e78797a29","base_fee_per_gas":"122747440","block_hash":"0x7524d779d328159e4d9ee8a4b04c4b251261da9a6da1d1461243125faa447227","transactions_root":"0x7e8a3391a77eaea563bf4e0ca4cf3190425b591ed8572818924c38f7e423c257","withdrawals_root":"0x61a5653b614ec3db0745ae5568e6de683520d84bc3db2dedf6a5158049cee807","blob_gas_used":"0","excess_blob_gas":"0"},"bls_to_execution_changes":[],"blob_kzg_commitments":[]}},"signature":"0x94320e6aecd65da3ef3e55e45208978844b262fe21cacbb0a8448b2caf21e8619b205c830116d8aad0a2c55d879fb571123a3fcf31b515f9508eb346ecd3de2db07cea6700379c00831cfb439f4aeb3bfa164395367c8d8befb92aa6682eae51"}`)
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/node/syncing", target), http.MethodPost, body, false)
}

func getAttestationsForBlock(ctx context.Context, target string, block int) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/beacon/blocks/%v/attestations", target, block), http.MethodGet, nil, false)
}

func getSyncing(ctx context.Context, target string) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/node/syncing", target), http.MethodGet, nil, false)
}

func getProposalDutiesForEpoch(ctx context.Context, target string, epoch int) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/duties/proposer/%v", target, epoch), http.MethodGet, nil, true)
}

func getAttestationData(ctx context.Context, target string, slot int, committeeIndex int) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/attestation_data?slot=%v&committee_index=%v", target, slot, committeeIndex), http.MethodGet, nil, true)
}

func submitAttestationObject(ctx context.Context, target string) (time.Duration, error) {
	body := strings.NewReader(`{{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}}`)
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/beacon/pool/attestations", target), http.MethodPost, body, false)
}

func getAggregateAttestations(ctx context.Context, target string, slot int, attestationDataRoot string) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/aggregate_attestation?slot=%v&attestation_data_root=%v", target, slot, attestationDataRoot), http.MethodGet, nil, false)
}

func aggregateAndProofs(ctx context.Context, target string) (time.Duration, error) {
	body := strings.NewReader(`[{"message":{"aggregator_index":"1","aggregate":{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}},"selection_proof":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}]`)
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/aggregate_and_proofs", target), http.MethodPost, body, false)
}
