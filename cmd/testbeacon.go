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
	ProposerDuty        time.Duration
}

type Simulation struct {
	GeneralRequests SimulationGeneralRequests
	Validators      []SimulationPerValidator
}

type SimulationPerValidator struct {
	Attestation SimulationAttestation
}

type SimulationAttestation struct {
	AttestationGetDuties SimulationValues
	AttestationPostData  SimulationValues
	SimulationValues
}

type SimulationGeneralRequests struct {
	AttestationsForBlock   SimulationValues
	ProposerDutiesForEpoch SimulationValues
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
	)

	intensity := RequestsIntensity{
		AttestationDuty:     slotTime,
		AggregatorDuty:      slotTime * 2,
		SyncCommitteeDuties: epochTime,
		ProposerDuty:        epochTime / 2,
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
	proposerDutiesForEpochCh := make(chan time.Duration)
	proposerDutiesForEpochAll := []time.Duration{}
	syncingCh := make(chan time.Duration)
	syncingAll := []time.Duration{}
	log.Info(ctx, "Starting general cluster requests...")
	slot, err := getCurrentSlot(ctx, target)
	if err != nil {
		log.Error(ctx, "Failed to get current slot", err)
		slot = 1
	}
	go clusterGeneralRequests(ctx, target, slot, slotTime, simulationDuration, attestationsForBlockCh, proposerDutiesForEpochCh, syncingCh)

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
		case result, ok := <-proposerDutiesForEpochCh:
			if !ok {
				finished = true
				continue
			}
			proposerDutiesForEpochAll = append(proposerDutiesForEpochAll, result)
		case result, ok := <-syncingCh:
			if !ok {
				finished = true
				continue
			}
			syncingAll = append(syncingAll, result)
		}
	}

	attestationsForBlockValues := simulationValuesFromSlice(attestationsForBlockAll)
	proposerDutiesForEpochValues := simulationValuesFromSlice(proposerDutiesForEpochAll)
	syncingValues := simulationValuesFromSlice(syncingAll)

	generalResults := SimulationGeneralRequests{
		AttestationsForBlock:   attestationsForBlockValues,
		ProposerDutiesForEpoch: proposerDutiesForEpochValues,
		Syncing:                syncingValues,
	}

	log.Info(ctx, "General requests simulation for cluster finished")
	resultCh <- generalResults
}

func clusterGeneralRequests(ctx context.Context, target string, slot int, slotTime time.Duration, simulationDuration time.Duration, attestationsForBlockCh chan time.Duration, proposerDutiesForEpochCh chan time.Duration, syncingCh chan time.Duration) {
	defer func() {
		close(proposerDutiesForEpochCh)
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
			submitResult, err := getProposerDutiesForEpoch(ctx, target, slot/slotsInEpoch)
			if err != nil {
				log.Error(ctx, "Unexpected getProposerDutiesForEpoch failure", err)
			}
			attestationsForBlockCh <- attestationsResult
			proposerDutiesForEpochCh <- submitResult
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

	// start proposer duties
	// TODO

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
		}
		// add propose channels
		// TODO
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

	// synthesize proposer results
	// TODO

	log.Info(ctx, "Simulation for validator finished")
	resultCh <- SimulationPerValidator{
		Attestation: attestationResult,
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
			slot++
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

func getAttestationsForBlock(ctx context.Context, target string, block int) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/beacon/blocks/%v/attestations", target, block), http.MethodGet, nil, false)
}

func getSyncing(ctx context.Context, target string) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/node/syncing", target), http.MethodGet, nil, false)
}

func getProposerDutiesForEpoch(ctx context.Context, target string, epoch int) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/duties/proposer/%v", target, epoch), http.MethodGet, nil, true)
}

func getAttestationData(ctx context.Context, target string, slot int, committeeIndex int) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/attestation_data?slot=%v&committee_index=%v", target, slot, committeeIndex), http.MethodGet, nil, true)
}

func submitAttestationObject(ctx context.Context, target string) (time.Duration, error) {
	body := strings.NewReader(`{
    "aggregation_bits": "0x01",
    "signature": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505",
    "data": {
      "slot": "1",
      "index": "1",
      "beacon_block_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
      "source": {
        "epoch": "1",
        "root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
      },
      "target": {
        "epoch": "1",
        "root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
      }
    }
  }`)

	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/beacon/pool/attestations", target), http.MethodPost, body, false)
}
