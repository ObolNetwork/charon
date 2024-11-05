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
	SimulationVerbose    bool
}

type testCaseBeacon func(context.Context, *testBeaconConfig, string) testResult

type SimulationValues struct {
	All    []Duration `json:",omitempty"`
	Min    Duration
	Max    Duration
	Median Duration
	Avg    Duration
}

type RequestsIntensity struct {
	AttestationDuty        time.Duration
	AggregatorDuty         time.Duration
	ProposalDuty           time.Duration
	SyncCommitteeSubmit    time.Duration
	SyncCommitteeProduce   time.Duration
	SyncCommitteeSubscribe time.Duration
}

type DutiesPerformed struct {
	Attestation   bool
	Aggregation   bool
	Proposal      bool
	SyncCommittee bool
}

type Simulation struct {
	GeneralRequests    SimulationGeneralRequests
	ValidatorsOverview SimulationAllValidators
}

type SimulationAllValidators struct {
	Averaged      SimulationPerValidator
	AllValidators []SimulationPerValidator `json:",omitempty"`
}

type SimulationPerValidator struct {
	Attestation   SimulationAttestation
	Aggregation   SimulationAggregation
	Proposal      SimulationProposal
	SyncCommittee SimulationSyncCommittee
	SimulationValues
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

type SimulationSyncCommittee struct {
	SubmitSyncCommittees             SimulationValues
	ProduceSyncCommitteeContribution SimulationValues
	SyncCommitteeSubscription        SimulationValues
}

type SimulationGeneralRequests struct {
	AttestationsForBlock        SimulationValues
	ProposalDutiesForEpoch      SimulationValues
	Syncing                     SimulationValues
	PeerCount                   SimulationValues
	BeaconCommitteeSubscription SimulationValues
	DutiesAttesterForEpoch      SimulationValues
	DutiesSyncCommitteeForEpoch SimulationValues
	BeaconHeadValidators        SimulationValues
	BeaconGenesis               SimulationValues
	PrepBeaconProposer          SimulationValues
	ConfigSpec                  SimulationValues
	NodeVersion                 SimulationValues
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
	committeeSizePerSlot          = 64
	subCommitteeSize              = 4
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
	cmd.Flags().BoolVar(&config.SimulationVerbose, "simulation-verbose", false, "Show results for each request and each validator.")
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

	// setup simulation variables
	totalValidatorsCount := 10
	syncCommitteeValidatorsCount := 1
	proposalValidatorsCount := 3
	attesterValidatorsCount := totalValidatorsCount - syncCommitteeValidatorsCount - proposalValidatorsCount
	intensity := RequestsIntensity{
		AttestationDuty:        slotTime,
		AggregatorDuty:         slotTime * 2,
		ProposalDuty:           slotTime * 4,
		SyncCommitteeSubmit:    slotTime,
		SyncCommitteeProduce:   slotTime * 4,
		SyncCommitteeSubscribe: epochTime,
	}
	duration := time.Duration(conf.SimulationDuration)*slotTime + time.Second
	var wg sync.WaitGroup

	log.Info(ctx, "Running simulation for 10 validators...",
		z.Any("validators", totalValidatorsCount),
		z.Any("target", target),
		z.Any("duration_in_slots", conf.SimulationDuration),
		z.Any("slot_duration", slotTime),
	)

	// start general cluster requests
	simulationGeneralResCh := make(chan SimulationGeneralRequests, 1)
	var simulationGeneralRes SimulationGeneralRequests
	wg.Add(1)
	log.Info(ctx, "Starting general cluster requests...")
	go singleClusterSimulation(ctx, duration, target, simulationGeneralResCh, &wg)

	// start validator requests
	simulationResCh := make(chan SimulationPerValidator, totalValidatorsCount)
	simulationResAll := []SimulationPerValidator{}

	log.Info(ctx, "Starting validators performing duties attestation, aggregation, proposal, sync committee...",
		z.Any("validators", syncCommitteeValidatorsCount),
	)
	syncCommitteeValidatorsDuties := DutiesPerformed{Attestation: true, Aggregation: true, Proposal: true, SyncCommittee: true}
	for range syncCommitteeValidatorsCount {
		wg.Add(1)
		go singleValidatorSimulation(ctx, duration, target, simulationResCh, intensity, syncCommitteeValidatorsDuties, &wg)
	}

	log.Info(ctx, "Starting validators performing duties attestation, aggregation, proposal...",
		z.Any("validators", proposalValidatorsCount),
	)
	proposalValidatorsDuties := DutiesPerformed{Attestation: true, Aggregation: true, Proposal: true, SyncCommittee: false}
	for range proposalValidatorsCount {
		wg.Add(1)
		go singleValidatorSimulation(ctx, duration, target, simulationResCh, intensity, proposalValidatorsDuties, &wg)
	}

	log.Info(ctx, "Starting validators performing duties attestation, aggregation...",
		z.Any("validators", attesterValidatorsCount),
	)
	attesterValidatorsDuties := DutiesPerformed{Attestation: true, Aggregation: true, Proposal: false, SyncCommittee: false}
	for range attesterValidatorsCount {
		wg.Add(1)
		go singleValidatorSimulation(ctx, duration, target, simulationResCh, intensity, attesterValidatorsDuties, &wg)
	}

	log.Info(ctx, "Waiting for simulation to complete...")
	// evaluate results
	wg.Wait()
	close(simulationGeneralResCh)
	close(simulationResCh)
	log.Info(ctx, "Simulation finished, evaluating results...")
	simulationGeneralRes = <-simulationGeneralResCh
	for result := range simulationResCh {
		simulationResAll = append(simulationResAll, result)
	}

	averageValidatorResult := averageValidatorsResult(simulationResAll)

	finalSimulation := Simulation{
		GeneralRequests: simulationGeneralRes,
		ValidatorsOverview: SimulationAllValidators{
			Averaged:      averageValidatorResult,
			AllValidators: simulationResAll,
		},
	}

	if !conf.SimulationVerbose {
		finalSimulation = nonVerboseFinalSimulation(finalSimulation)
	}
	simulationResAllJSON, err := json.Marshal(finalSimulation)
	if err != nil {
		log.Error(ctx, "Failed to marshal simulation result", err)
	}
	err = os.WriteFile(filepath.Join(conf.SimulationFileDir, fmt.Sprintf("%v-validators.json", totalValidatorsCount)), simulationResAllJSON, 0o644) //nolint:gosec
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

func nonVerboseFinalSimulation(s Simulation) Simulation {
	s.ValidatorsOverview.AllValidators = []SimulationPerValidator{}

	s.ValidatorsOverview.Averaged.All = []Duration{}
	s.ValidatorsOverview.Averaged.Aggregation.All = []Duration{}
	s.ValidatorsOverview.Averaged.Aggregation.AggregationGetAggregationAttestations.All = []Duration{}
	s.ValidatorsOverview.Averaged.Aggregation.AggregationSubmitAggregateAndProofs.All = []Duration{}
	s.ValidatorsOverview.Averaged.Attestation.All = []Duration{}
	s.ValidatorsOverview.Averaged.Attestation.AttestationGetDuties.All = []Duration{}
	s.ValidatorsOverview.Averaged.Attestation.AttestationPostData.All = []Duration{}
	s.ValidatorsOverview.Averaged.Proposal.All = []Duration{}
	s.ValidatorsOverview.Averaged.Proposal.ProposalProduceBlock.All = []Duration{}
	s.ValidatorsOverview.Averaged.Proposal.ProposalPublishBlindedBlock.All = []Duration{}
	s.ValidatorsOverview.Averaged.SyncCommittee.ProduceSyncCommitteeContribution.All = []Duration{}
	s.ValidatorsOverview.Averaged.SyncCommittee.SubmitSyncCommittees.All = []Duration{}
	s.ValidatorsOverview.Averaged.SyncCommittee.SyncCommitteeSubscription.All = []Duration{}

	s.GeneralRequests.AttestationsForBlock.All = []Duration{}
	s.GeneralRequests.ProposalDutiesForEpoch.All = []Duration{}
	s.GeneralRequests.Syncing.All = []Duration{}

	return s
}

func singleClusterSimulation(ctx context.Context, simulationDuration time.Duration, target string, resultCh chan SimulationGeneralRequests, wg *sync.WaitGroup) {
	defer wg.Done()
	// per slot requests
	attestationsForBlockCh := make(chan time.Duration)
	attestationsForBlockAll := []time.Duration{}
	proposalDutiesForEpochCh := make(chan time.Duration)
	proposalDutiesForEpochAll := []time.Duration{}
	// per 10 sec requests
	syncingCh := make(chan time.Duration)
	syncingAll := []time.Duration{}
	// per minute requests
	peerCountCh := make(chan time.Duration)
	peerCountAll := []time.Duration{}
	// per 12 slots requests
	beaconCommitteeSubCh := make(chan time.Duration)
	beaconCommitteeSubAll := []time.Duration{}
	// 3 times per epoch - at first slot of the epoch, at the last but one and the last
	dutiesAttesterCh := make(chan time.Duration)
	dutiesAttesterAll := []time.Duration{}
	// 3 times per epoch - 10 seconds before the epoch - call for the epoch, at the time of epoch - call for the epoch and call for the epoch+256
	dutiesSyncCommitteeCh := make(chan time.Duration)
	dutiesSyncCommitteeAll := []time.Duration{}
	// once per epoch, at the beginning of the epoch
	beaconHeadValidatorsCh := make(chan time.Duration)
	beaconHeadValidatorsAll := []time.Duration{}
	beaconGenesisCh := make(chan time.Duration)
	beaconGenesisAll := []time.Duration{}
	prepBeaconProposerCh := make(chan time.Duration)
	prepBeaconProposerAll := []time.Duration{}
	configSpecCh := make(chan time.Duration)
	configSpecAll := []time.Duration{}
	nodeVersionCh := make(chan time.Duration) // 7 seconds after start of epoch
	nodeVersionAll := []time.Duration{}
	// two endpoints called are not included:
	// 1. /eth/v1/config/fork_schedule - it seemed at random every 240-600 epochs, didn't seem worth to do it
	// 2. /eth/v1/events?topics=head - it happened only once for 26 hours, it didn't seem related to anything

	go clusterGeneralRequests(ctx, target, slotTime, simulationDuration,
		attestationsForBlockCh, proposalDutiesForEpochCh, syncingCh,
		peerCountCh, beaconCommitteeSubCh, dutiesAttesterCh,
		dutiesSyncCommitteeCh, beaconHeadValidatorsCh, beaconGenesisCh,
		prepBeaconProposerCh, configSpecCh, nodeVersionCh)

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
		case result, ok := <-peerCountCh:
			if !ok {
				finished = true
				continue
			}
			peerCountAll = append(peerCountAll, result)
		case result, ok := <-beaconCommitteeSubCh:
			if !ok {
				finished = true
				continue
			}
			beaconCommitteeSubAll = append(beaconCommitteeSubAll, result)
		case result, ok := <-dutiesAttesterCh:
			if !ok {
				finished = true
				continue
			}
			dutiesAttesterAll = append(dutiesAttesterAll, result)
		case result, ok := <-dutiesSyncCommitteeCh:
			if !ok {
				finished = true
				continue
			}
			dutiesSyncCommitteeAll = append(dutiesSyncCommitteeAll, result)
		case result, ok := <-beaconHeadValidatorsCh:
			if !ok {
				finished = true
				continue
			}
			beaconHeadValidatorsAll = append(beaconHeadValidatorsAll, result)
		case result, ok := <-beaconGenesisCh:
			if !ok {
				finished = true
				continue
			}
			beaconGenesisAll = append(beaconGenesisAll, result)
		case result, ok := <-prepBeaconProposerCh:
			if !ok {
				finished = true
				continue
			}
			prepBeaconProposerAll = append(prepBeaconProposerAll, result)
		case result, ok := <-configSpecCh:
			if !ok {
				finished = true
				continue
			}
			configSpecAll = append(configSpecAll, result)
		case result, ok := <-nodeVersionCh:
			if !ok {
				finished = true
				continue
			}
			nodeVersionAll = append(nodeVersionAll, result)
		}
	}

	attestationsForBlockValues := simulationValuesFromTime(attestationsForBlockAll)
	proposalDutiesForEpochValues := simulationValuesFromTime(proposalDutiesForEpochAll)
	syncingValues := simulationValuesFromTime(syncingAll)
	peerCountValues := simulationValuesFromTime(peerCountAll)
	beaconCommitteeSubValues := simulationValuesFromTime(beaconCommitteeSubAll)
	dutiesAttesterValues := simulationValuesFromTime(dutiesAttesterAll)
	dutiesSyncCommitteeValues := simulationValuesFromTime(dutiesSyncCommitteeAll)
	beaconHeadValidatorsValues := simulationValuesFromTime(beaconHeadValidatorsAll)
	beaconGenesisValues := simulationValuesFromTime(beaconGenesisAll)
	prepBeaconProposerValues := simulationValuesFromTime(prepBeaconProposerAll)
	configSpecValues := simulationValuesFromTime(configSpecAll)
	nodeVersionValues := simulationValuesFromTime(nodeVersionAll)

	generalResults := SimulationGeneralRequests{
		AttestationsForBlock:        attestationsForBlockValues,
		ProposalDutiesForEpoch:      proposalDutiesForEpochValues,
		Syncing:                     syncingValues,
		PeerCount:                   peerCountValues,
		BeaconCommitteeSubscription: beaconCommitteeSubValues,
		DutiesAttesterForEpoch:      dutiesAttesterValues,
		DutiesSyncCommitteeForEpoch: dutiesSyncCommitteeValues,
		BeaconHeadValidators:        beaconHeadValidatorsValues,
		BeaconGenesis:               beaconGenesisValues,
		PrepBeaconProposer:          prepBeaconProposerValues,
		ConfigSpec:                  configSpecValues,
		NodeVersion:                 nodeVersionValues,
	}

	resultCh <- generalResults
}

func clusterGeneralRequests(
	ctx context.Context, target string, slotTime time.Duration, simulationDuration time.Duration,
	attestationsForBlockCh chan time.Duration, proposalDutiesForEpochCh chan time.Duration, syncingCh chan time.Duration,
	peerCountCh chan time.Duration, beaconCommitteeSubCh chan time.Duration, dutiesAttesterCh chan time.Duration,
	dutiesSyncCommitteeCh chan time.Duration, beaconHeadValidatorsCh chan time.Duration, beaconGenesisCh chan time.Duration,
	prepBeaconProposerCh chan time.Duration, configSpecCh chan time.Duration, nodeVersionCh chan time.Duration,
) {
	defer func() {
		close(proposalDutiesForEpochCh)
		close(attestationsForBlockCh)
		close(syncingCh)
		close(peerCountCh)
		close(beaconCommitteeSubCh)
		close(dutiesAttesterCh)
		close(dutiesSyncCommitteeCh)
		close(beaconHeadValidatorsCh)
		close(beaconGenesisCh)
		close(prepBeaconProposerCh)
		close(configSpecCh)
		close(nodeVersionCh)
	}()
	// slot ticker
	tickerSlot := time.NewTicker(slotTime)
	defer tickerSlot.Stop()
	// 12 slots ticker
	ticker12Slots := time.NewTicker(12 * slotTime)
	defer ticker12Slots.Stop()
	// 10 sec ticker
	ticker10Sec := time.NewTicker(10 * time.Second)
	defer ticker10Sec.Stop()
	// minute ticker
	tickerMinute := time.NewTicker(time.Minute)
	defer tickerMinute.Stop()

	slot, err := getCurrentSlot(ctx, target)
	if err != nil {
		log.Error(ctx, "Failed to get current slot", err)
		slot = 1
	}

	pingCtx, cancel := context.WithTimeout(ctx, simulationDuration)
	defer cancel()

	for pingCtx.Err() == nil {
		select {
		case <-tickerSlot.C:
			slot++
			epoch := slot / slotsInEpoch
			// requests executed at every slot
			attestationsResult, err := getAttestationsForBlock(ctx, target, slot-6)
			if err != nil {
				log.Error(ctx, "Unexpected getAttestationsForBlock failure", err)
			}
			attestationsForBlockCh <- attestationsResult
			submitResult, err := getProposalDutiesForEpoch(ctx, target, epoch)
			if err != nil {
				log.Error(ctx, "Unexpected getProposalDutiesForEpoch failure", err)
			}
			proposalDutiesForEpochCh <- submitResult
			// requests executed at the first slot of the epoch
			if slot%slotsInEpoch == 0 {
				dutiesAttesterResult, err := getAttesterDutiesForEpoch(ctx, target, epoch)
				if err != nil {
					log.Error(ctx, "Unexpected getAttesterDutiesForEpoch failure", err)
				}
				dutiesAttesterCh <- dutiesAttesterResult

				dutiesSyncCommitteeResult, err := getSyncCommitteeDutiesForEpoch(ctx, target, epoch)
				if err != nil {
					log.Error(ctx, "Unexpected getSyncCommitteeDutiesForEpoch failure", err)
				}
				dutiesSyncCommitteeCh <- dutiesSyncCommitteeResult

				beaconHeadValidatorsResult, err := beaconHeadValidators(ctx, target)
				if err != nil {
					log.Error(ctx, "Unexpected beaconHeadValidators failure", err)
				}
				beaconHeadValidatorsCh <- beaconHeadValidatorsResult

				beaconGenesisResult, err := beaconGenesis(ctx, target)
				if err != nil {
					log.Error(ctx, "Unexpected beaconGenesis failure", err)
				}
				beaconGenesisCh <- beaconGenesisResult

				prepBeaconProposerResult, err := prepBeaconProposer(ctx, target)
				if err != nil {
					log.Error(ctx, "Unexpected prepBeaconProposer failure", err)
				}
				prepBeaconProposerCh <- prepBeaconProposerResult

				configSpecResult, err := configSpec(ctx, target)
				if err != nil {
					log.Error(ctx, "Unexpected configSpec failure", err)
				}
				configSpecCh <- configSpecResult

				nodeVersionResult, err := nodeVersion(ctx, target)
				if err != nil {
					log.Error(ctx, "Unexpected nodeVersion failure", err)
				}
				nodeVersionCh <- nodeVersionResult
			}
			// requests executed at the last but one slot of the epoch
			if slot%slotsInEpoch == slotsInEpoch-2 {
				dutiesAttesterResult, err := getAttesterDutiesForEpoch(ctx, target, epoch)
				if err != nil {
					log.Error(ctx, "Unexpected getAttesterDutiesForEpoch failure", err)
				}
				dutiesAttesterCh <- dutiesAttesterResult
			}
			// requests executed at the last slot of the epoch
			if slot%slotsInEpoch == slotsInEpoch-1 {
				dutiesAttesterResult, err := getAttesterDutiesForEpoch(ctx, target, epoch)
				if err != nil {
					log.Error(ctx, "Unexpected getAttesterDutiesForEpoch failure", err)
				}
				dutiesAttesterCh <- dutiesAttesterResult

				dutiesSyncCommitteeResult, err := getSyncCommitteeDutiesForEpoch(ctx, target, epoch)
				if err != nil {
					log.Error(ctx, "Unexpected getSyncCommitteeDutiesForEpoch failure", err)
				}
				dutiesSyncCommitteeCh <- dutiesSyncCommitteeResult

				dutiesSyncCommitteeResultFuture, err := getSyncCommitteeDutiesForEpoch(ctx, target, epoch+256)
				if err != nil {
					log.Error(ctx, "Unexpected getSyncCommitteeDutiesForEpoch for the future epoch failure", err)
				}
				dutiesSyncCommitteeCh <- dutiesSyncCommitteeResultFuture
			}
		case <-ticker12Slots.C:
			beaconCommitteeSubResult, err := beaconCommitteeSub(ctx, target)
			if err != nil {
				log.Error(ctx, "Unexpected beaconCommitteeSub failure", err)
			}
			beaconCommitteeSubCh <- beaconCommitteeSubResult
		case <-ticker10Sec.C:
			getSyncingResult, err := getSyncing(ctx, target)
			if err != nil {
				log.Error(ctx, "Unexpected getSyncing failure", err)
			}
			syncingCh <- getSyncingResult
		case <-tickerMinute.C:
			peerCountResult, err := getPeerCount(ctx, target)
			if err != nil {
				log.Error(ctx, "Unexpected getPeerCount failure", err)
			}
			peerCountCh <- peerCountResult
		case <-pingCtx.Done():
		}
	}
}

func singleValidatorSimulation(ctx context.Context, simulationDuration time.Duration, target string, resultCh chan SimulationPerValidator, intensity RequestsIntensity, dutiesPerformed DutiesPerformed, wg *sync.WaitGroup) {
	defer wg.Done()
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
	if dutiesPerformed.Attestation {
		go attestationDuty(ctx, target, slot, simulationDuration, intensity.AttestationDuty, getAttestationDataCh, submitAttestationObjectCh)
	}

	// aggregations
	getAggregateAttestationsCh := make(chan time.Duration)
	getAggregateAttestationsAll := []time.Duration{}
	submitAggregateAndProofsCh := make(chan time.Duration)
	submitAggregateAndProofsAll := []time.Duration{}
	if dutiesPerformed.Aggregation {
		go aggregationDuty(ctx, target, slot, simulationDuration, intensity.AggregatorDuty, getAggregateAttestationsCh, submitAggregateAndProofsCh)
	}

	// proposals
	produceBlockCh := make(chan time.Duration)
	produceBlockAll := []time.Duration{}
	publishBlindedBlockCh := make(chan time.Duration)
	publishBlindedBlockAll := []time.Duration{}
	if dutiesPerformed.Proposal {
		go proposalDuty(ctx, target, slot, simulationDuration, intensity.ProposalDuty, produceBlockCh, publishBlindedBlockCh)
	}

	// sync_committee
	submitSyncCommitteesCh := make(chan time.Duration)
	submitSyncCommitteesAll := []time.Duration{}
	produceSyncCommitteeContributionCh := make(chan time.Duration)
	produceSyncCommitteeContributionAll := []time.Duration{}
	syncCommitteeSubscriptionCh := make(chan time.Duration)
	syncCommitteeSubscriptionAll := []time.Duration{}
	if dutiesPerformed.SyncCommittee {
		go syncCommitteeDuty(ctx, target, slot,
			simulationDuration, intensity.SyncCommitteeSubmit, intensity.SyncCommitteeProduce, intensity.SyncCommitteeSubscribe,
			submitSyncCommitteesCh, produceSyncCommitteeContributionCh, syncCommitteeSubscriptionCh)
	}

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
		case result, ok := <-submitSyncCommitteesCh:
			if !ok {
				finished = true
				continue
			}
			submitSyncCommitteesAll = append(submitSyncCommitteesAll, result)
		case result, ok := <-produceSyncCommitteeContributionCh:
			if !ok {
				finished = true
				continue
			}
			produceSyncCommitteeContributionAll = append(produceSyncCommitteeContributionAll, result)
		case result, ok := <-syncCommitteeSubscriptionCh:
			if !ok {
				finished = true
				continue
			}
			syncCommitteeSubscriptionAll = append(syncCommitteeSubscriptionAll, result)
		}
	}

	var allRequests []time.Duration

	// attestation results grouping
	var attestationResult SimulationAttestation
	if dutiesPerformed.Attestation {
		getSimulationValues := simulationValuesFromTime(getAttestationDataAll)
		submitSimulationValues := simulationValuesFromTime(submitAttestationObjectAll)

		cumulativeAttestation := []time.Duration{}
		for i := range getAttestationDataAll {
			cumulativeAttestation = append(cumulativeAttestation, getAttestationDataAll[i]+submitAttestationObjectAll[i])
		}
		cumulativeSimulationValues := simulationValuesFromTime(cumulativeAttestation)
		allRequests = append(allRequests, cumulativeAttestation...)

		attestationResult = SimulationAttestation{
			AttestationGetDuties: getSimulationValues,
			AttestationPostData:  submitSimulationValues,
			SimulationValues:     cumulativeSimulationValues,
		}
	}

	// aggregation results grouping
	var aggregationResults SimulationAggregation
	if dutiesPerformed.Aggregation {
		getAggregateSimulationValues := simulationValuesFromTime(getAggregateAttestationsAll)
		submitAggregateSimulationValues := simulationValuesFromTime(submitAggregateAndProofsAll)

		cumulativeAggregations := []time.Duration{}
		for i := range getAggregateAttestationsAll {
			cumulativeAggregations = append(cumulativeAggregations, getAggregateAttestationsAll[i]+submitAggregateAndProofsAll[i])
		}
		cumulativeAggregationsSimulationValues := simulationValuesFromTime(cumulativeAggregations)
		allRequests = append(allRequests, cumulativeAggregations...)

		aggregationResults = SimulationAggregation{
			AggregationGetAggregationAttestations: getAggregateSimulationValues,
			AggregationSubmitAggregateAndProofs:   submitAggregateSimulationValues,
			SimulationValues:                      cumulativeAggregationsSimulationValues,
		}
	}

	// proposal results grouping
	var proposalResults SimulationProposal
	if dutiesPerformed.Proposal {
		produceBlockValues := simulationValuesFromTime(produceBlockAll)
		publishBlindedBlockValues := simulationValuesFromTime(publishBlindedBlockAll)

		cumulativeProposals := []time.Duration{}
		for i := range produceBlockAll {
			cumulativeProposals = append(cumulativeProposals, produceBlockAll[i]+publishBlindedBlockAll[i])
		}
		cumulativeProposalsSimulationValues := simulationValuesFromTime(cumulativeProposals)
		allRequests = append(allRequests, cumulativeProposals...)

		proposalResults = SimulationProposal{
			ProposalProduceBlock:        produceBlockValues,
			ProposalPublishBlindedBlock: publishBlindedBlockValues,
			SimulationValues:            cumulativeProposalsSimulationValues,
		}
	}

	// sync committee results grouping
	var syncCommitteeResults SimulationSyncCommittee
	if dutiesPerformed.SyncCommittee {
		submitSyncCommitteesValues := simulationValuesFromTime(submitSyncCommitteesAll)
		allRequests = append(allRequests, submitSyncCommitteesAll...)
		produceSyncCommitteeContributionValues := simulationValuesFromTime(produceSyncCommitteeContributionAll)
		allRequests = append(allRequests, produceSyncCommitteeContributionAll...)
		syncCommitteeSubscriptionValues := simulationValuesFromTime(syncCommitteeSubscriptionAll)
		allRequests = append(allRequests, syncCommitteeSubscriptionAll...)

		syncCommitteeResults = SimulationSyncCommittee{
			SubmitSyncCommittees:             submitSyncCommitteesValues,
			ProduceSyncCommitteeContribution: produceSyncCommitteeContributionValues,
			SyncCommitteeSubscription:        syncCommitteeSubscriptionValues,
		}
	}

	allResult := simulationValuesFromTime(allRequests)

	resultCh <- SimulationPerValidator{
		Attestation:      attestationResult,
		Aggregation:      aggregationResults,
		Proposal:         proposalResults,
		SyncCommittee:    syncCommitteeResults,
		SimulationValues: allResult,
	}
}

func simulationValuesFromTime(s []time.Duration) SimulationValues {
	if len(s) == 0 {
		return SimulationValues{
			All:    []Duration{},
			Min:    Duration{0},
			Max:    Duration{0},
			Median: Duration{0},
			Avg:    Duration{0},
		}
	}
	sort.Slice(s, func(i, j int) bool {
		return s[i] < s[j]
	})
	minVal := s[0]
	maxVal := s[len(s)-1]
	medianVal := s[len(s)/2]
	var sum time.Duration
	all := []Duration{}
	for _, t := range s {
		sum += t
		all = append(all, Duration{t})
	}
	avgVal := time.Duration(int(sum.Nanoseconds()) / len(s))

	return SimulationValues{
		All:    all,
		Min:    Duration{minVal},
		Max:    Duration{maxVal},
		Median: Duration{medianVal},
		Avg:    Duration{avgVal},
	}
}

func simulationValuesFromDuration(s []Duration) SimulationValues {
	if len(s) == 0 {
		return SimulationValues{
			All:    []Duration{},
			Min:    Duration{0},
			Max:    Duration{0},
			Median: Duration{0},
			Avg:    Duration{0},
		}
	}
	sort.Slice(s, func(i, j int) bool {
		return s[i].Duration < s[j].Duration
	})
	minVal := s[0]
	maxVal := s[len(s)-1]
	medianVal := s[len(s)/2]
	var sum time.Duration
	all := []Duration{}
	for _, t := range s {
		sum += t.Duration
		all = append(all, t)
	}
	avgVal := time.Duration(int(sum.Nanoseconds()) / len(s))

	return SimulationValues{
		All:    all,
		Min:    minVal,
		Max:    maxVal,
		Median: medianVal,
		Avg:    Duration{avgVal},
	}
}

func averageValidatorsResult(s []SimulationPerValidator) SimulationPerValidator {
	if len(s) == 0 {
		return SimulationPerValidator{}
	}

	var attestation, attestationGetDuties, attestationPostData,
		aggregation, aggregationGetAggregationAttestations, aggregationSubmitAggregateAndProofs,
		proposal, proposalProduceBlock, proposalPublishBlindedBlock,
		syncCommitteeSubmit, syncCommitteeContribution, syncCommitteeSusbscription,
		all []Duration

	for _, sim := range s {
		attestationGetDuties = append(attestationGetDuties, sim.Attestation.AttestationGetDuties.All...)
		attestationPostData = append(attestationPostData, sim.Attestation.AttestationPostData.All...)
		attestation = append(attestation, sim.Attestation.All...)
		aggregationGetAggregationAttestations = append(aggregationGetAggregationAttestations, sim.Aggregation.AggregationGetAggregationAttestations.All...)
		aggregationSubmitAggregateAndProofs = append(aggregationSubmitAggregateAndProofs, sim.Aggregation.AggregationSubmitAggregateAndProofs.All...)
		aggregation = append(aggregation, sim.Aggregation.All...)
		proposalProduceBlock = append(proposalProduceBlock, sim.Proposal.ProposalProduceBlock.All...)
		proposalPublishBlindedBlock = append(proposalPublishBlindedBlock, sim.Proposal.ProposalPublishBlindedBlock.All...)
		proposal = append(proposal, sim.Proposal.All...)
		syncCommitteeSubmit = append(syncCommitteeSubmit, sim.SyncCommittee.SubmitSyncCommittees.All...)
		syncCommitteeContribution = append(syncCommitteeContribution, sim.SyncCommittee.ProduceSyncCommitteeContribution.All...)
		syncCommitteeSusbscription = append(syncCommitteeSusbscription, sim.SyncCommittee.SubmitSyncCommittees.All...)
		all = append(all, sim.All...)
	}

	return SimulationPerValidator{
		Attestation: SimulationAttestation{
			AttestationGetDuties: simulationValuesFromDuration(attestationGetDuties),
			AttestationPostData:  simulationValuesFromDuration(attestationPostData),
			SimulationValues:     simulationValuesFromDuration(attestation),
		},
		Aggregation: SimulationAggregation{
			AggregationGetAggregationAttestations: simulationValuesFromDuration(aggregationGetAggregationAttestations),
			AggregationSubmitAggregateAndProofs:   simulationValuesFromDuration(aggregationSubmitAggregateAndProofs),
			SimulationValues:                      simulationValuesFromDuration(aggregation),
		},
		Proposal: SimulationProposal{
			ProposalProduceBlock:        simulationValuesFromDuration(proposalProduceBlock),
			ProposalPublishBlindedBlock: simulationValuesFromDuration(proposalPublishBlindedBlock),
			SimulationValues:            simulationValuesFromDuration(proposal),
		},
		SyncCommittee: SimulationSyncCommittee{
			SubmitSyncCommittees:             simulationValuesFromDuration(syncCommitteeSubmit),
			ProduceSyncCommitteeContribution: simulationValuesFromDuration(syncCommitteeContribution),
			SyncCommitteeSubscription:        simulationValuesFromDuration(syncCommitteeSusbscription),
		},
		SimulationValues: simulationValuesFromDuration(all),
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
		case <-pingCtx.Done():
		case <-ticker.C:
			slot += int(tickTime.Seconds()) / int(slotTime.Seconds())
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
		}
	}
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
		case <-pingCtx.Done():
		case <-ticker.C:
			slot += int(tickTime.Seconds())/int(slotTime.Seconds()) + 1 // produce block for the next slot, as the current one might have already been proposed
			produceResult, err := produceBlock(ctx, target, slot, "0x1fe79e4193450abda94aec753895cfb2aac2c2a930b6bab00fbb27ef6f4a69f4400ad67b5255b91837982b4c511ae1d94eae1cf169e20c11bd417c1fffdb1f99f4e13e2de68f3b5e73f1de677d73cd43e44bf9b133a79caf8e5fad06738e1b0c")
			if err != nil {
				log.Error(ctx, "Unexpected produceBlock failure", err)
			}
			publishResult, err := publishBlindedBlock(ctx, target)
			if err != nil {
				log.Error(ctx, "Unexpected publishBlindedBlock failure", err)
			}
			produceBlockCh <- produceResult
			publishBlindedBlockCh <- publishResult
		}
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
		case <-pingCtx.Done():
		case <-ticker.C:
			slot += int(tickTime.Seconds()) / int(slotTime.Seconds())
			getResult, err := getAttestationData(ctx, target, slot, rand.Intn(committeeSizePerSlot)) //nolint:gosec // weak generator is not an issue here
			if err != nil {
				log.Error(ctx, "Unexpected getAttestationData failure", err)
			}
			submitResult, err := submitAttestationObject(ctx, target)
			if err != nil {
				log.Error(ctx, "Unexpected submitAttestationObject failure", err)
			}
			getAttestationDataCh <- getResult
			submitAttestationObjectCh <- submitResult
		}
	}
}

func syncCommitteeDuty(
	ctx context.Context, target string, slot int,
	simulationDuration time.Duration, tickTimeSubmit time.Duration, tickTimeProduce time.Duration, tickTimeSubscribe time.Duration,
	submitSyncCommitteesCh chan time.Duration, produceSyncCommitteeContributionCh chan time.Duration, syncCommitteeSubscriptionCh chan time.Duration,
) {
	defer close(submitSyncCommitteesCh)
	defer close(produceSyncCommitteeContributionCh)
	defer close(syncCommitteeSubscriptionCh)
	pingCtx, cancel := context.WithTimeout(ctx, simulationDuration)
	defer cancel()
	tickerSubmit := time.NewTicker(tickTimeSubmit)
	defer tickerSubmit.Stop()
	tickerProduce := time.NewTicker(tickTimeProduce)
	defer tickerProduce.Stop()
	tickerSubscribe := time.NewTicker(tickTimeSubscribe)
	defer tickerSubscribe.Stop()

	for pingCtx.Err() == nil {
		select {
		case <-pingCtx.Done():
		case <-tickerSubmit.C:
			submitResult, err := submitSyncCommittees(ctx, target)
			if err != nil {
				log.Error(ctx, "Unexpected submitSyncCommittees failure", err)
			}
			submitSyncCommitteesCh <- submitResult
		case <-tickerProduce.C:
			slot += int(tickTimeSubmit.Seconds()) / int(slotTime.Seconds())
			produceResult, err := produceSyncCommitteeContribution(ctx, target, slot, rand.Intn(subCommitteeSize), "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2") //nolint:gosec // weak generator is not an issue here
			if err != nil {
				log.Error(ctx, "Unexpected produceSyncCommitteeContribution failure", err)
			}
			produceSyncCommitteeContributionCh <- produceResult
		case <-tickerSubscribe.C:
			subscribeResult, err := syncCommitteeSubscription(ctx, target)
			if err != nil {
				log.Error(ctx, "Unexpected syncCommitteeSubscription failure", err)
			}
			syncCommitteeSubscriptionCh <- subscribeResult
		}
	}
}

func requestRTT(ctx context.Context, url string, method string, body io.Reader, expectedStatus int) (time.Duration, error) {
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

	if resp.StatusCode != expectedStatus {
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Warn(ctx, "Unexpected status code", nil, z.Int("status_code", resp.StatusCode), z.Int("expected_status_code", expectedStatus), z.Str("endpoint", url))
		} else {
			log.Warn(ctx, "Unexpected status code", nil, z.Int("status_code", resp.StatusCode), z.Int("expected_status_code", expectedStatus), z.Str("endpoint", url), z.Str("body", string(data)))
		}
	}

	return firstByte, nil
}

func produceBlock(ctx context.Context, target string, slot int, randaoReveal string) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v3/validator/blocks/%v?randao_reveal=%v", target, slot, randaoReveal), http.MethodGet, nil, 200)
}

func publishBlindedBlock(ctx context.Context, target string) (time.Duration, error) {
	body := strings.NewReader(`{"message":{"slot":"2872079","proposer_index":"1725813","parent_root":"0x05bea9b8e9cc28c4efa5586b4efac20b7a42c3112dbe144fb552b37ded249abd","state_root":"0x0138e6e8e956218aa534597a450a93c2c98f07da207077b4be05742279688da2","body":{"randao_reveal":"0x9880dad5a0e900906a1355da0697821af687b4c2cd861cd219f2d779c50a47d3c0335c08d840c86c167986ae0aaf50070b708fe93a83f66c99a4f931f9a520aebb0f5b11ca202c3d76343e30e49f43c0479e850af0e410333f7c59c4d37fa95a","eth1_data":{"deposit_root":"0x7dbea1a0af14d774da92d94a88d3bb1ae7abad16374da4db2c71dd086c84029e","deposit_count":"452100","block_hash":"0xc4bf450c9e362dcb2b50e76b45938c78d455acd1e1aec4e1ce4338ec023cd32a"},"graffiti":"0x636861726f6e2f76312e312e302d613139336638340000000000000000000000","proposer_slashings":[],"attester_slashings":[],"attestations":[{"aggregation_bits":"0xdbedbfa74eccaf3d7ef570bfdbbf84b4dffc5beede1c1f8b59feb8b3f2fbabdbdef3ceeb7b3dfdeeef8efcbdcd7bebbeff7adfff5ae3bf66bc5613feffef3deb987f7e7fff87ed6f8bbd1fffa57f1677efff646f0d3bd79fffdc5dfd78df6cf79fb7febff5dfdefb8e03","data":{"slot":"2872060","index":"12","beacon_block_root":"0x310506169f7f92dcd2bf00e8b4c2daac999566929395120fbbf4edd222e003eb","source":{"epoch":"89750","root":"0xcdb449d69e3e2d22378bfc2299ee1e9aeb1b2d15066022e854759dda73d1e219"},"target":{"epoch":"89751","root":"0x4ad0882f7adbb735c56b0b3f09d8e45dbd79db9528110f7117ec067f3a19eb0e"}},"signature":"0xa9d91d6cbc669ffcc8ba2435c633e0ec0eebecaa3acdcaa1454282ece1f816e8b853f00ba67ec1244703221efae4c834012819ca7b199354669f24ba8ab1c769f072c9f46b803082eac32e3611cd323eeb5b17fcd6201b41f3063834ff26ef53"}],"deposits":[],"voluntary_exits":[],"sync_aggregate":{"sync_committee_bits":"0xf9ff3ff7ffffb7dbfefddff5fffffefdbffffffffffedfefffffff7fbe9fdffffdb5feffffffbfdbefff3ffdf7f3fc6ff7fffbffff9df6fbbaf3beffefffffff","sync_committee_signature":"0xa9cf7d9f23a62e84f11851e2e4b3b929b1d03719a780b59ecba5daf57e21a0ceccaf13db4e1392a42e3603abeb839a2d16373dcdd5e696f11c5a809972c1e368d794f1c61d4d10b220df52616032f09b33912febf8c7a64f3ce067ab771c7ddf"},"execution_payload_header":{"parent_hash":"0x71c564f4a0c1dea921e8063fc620ccfa39c1b073e4ac0845ce7e9e6f909752de","fee_recipient":"0x148914866080716b10D686F5570631Fbb2207002","state_root":"0x89e74be562cd4a10eb20cdf674f65b1b0e53b33a7c3f2df848eb4f7e226742e0","receipts_root":"0x55b494ee1bb919e7abffaab1d5be05a109612c59a77406d929d77c0ce714f21d","logs_bloom":"0x20500886140245d001002010680c10411a2540420182810440a108800fc008440801180020011008004045005a2007826802e102000005c0c04030590004044810d0d20745c0904a4d583008a01758018001082024e40046000410020042400100012260220299a8084415e20002891224c132220010003a00006010020ed0c108920a13c0e200a1a00251100888c01408008132414068c88b028920440248209a280581a0e10800c14ea63082c1781308208b130508d4000400802d1224521094260912473404012810001503417b4050141100c1103004000c8900644560080472688450710084088800c4c80000c02008931188204c008009011784488060","prev_randao":"0xf4e9a4a7b88a3d349d779e13118b6d099f7773ec5323921343ac212df19c620f","block_number":"2643688","gas_limit":"30000000","gas_used":"24445884","timestamp":"1730367348","extra_data":"0x546974616e2028746974616e6275696c6465722e78797a29","base_fee_per_gas":"122747440","block_hash":"0x7524d779d328159e4d9ee8a4b04c4b251261da9a6da1d1461243125faa447227","transactions_root":"0x7e8a3391a77eaea563bf4e0ca4cf3190425b591ed8572818924c38f7e423c257","withdrawals_root":"0x61a5653b614ec3db0745ae5568e6de683520d84bc3db2dedf6a5158049cee807","blob_gas_used":"0","excess_blob_gas":"0"},"bls_to_execution_changes":[],"blob_kzg_commitments":[]}},"signature":"0x94320e6aecd65da3ef3e55e45208978844b262fe21cacbb0a8448b2caf21e8619b205c830116d8aad0a2c55d879fb571123a3fcf31b515f9508eb346ecd3de2db07cea6700379c00831cfb439f4aeb3bfa164395367c8d8befb92aa6682eae51"}`)
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v2/beacon/blinded", target), http.MethodPost, body, 404)
}

func getAttestationsForBlock(ctx context.Context, target string, block int) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/beacon/blocks/%v/attestations", target, block), http.MethodGet, nil, 200)
}

func getSyncing(ctx context.Context, target string) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/node/syncing", target), http.MethodGet, nil, 200)
}

func getPeerCount(ctx context.Context, target string) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/node/peer_count", target), http.MethodGet, nil, 200)
}

func beaconCommitteeSub(ctx context.Context, target string) (time.Duration, error) {
	body := strings.NewReader(`[{"validator_index":"1","committee_index":"1","committees_at_slot":"1","slot":"1","is_aggregator":true}]`)
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/beacon_committee_subscriptions", target), http.MethodPost, body, 200)
}

func getAttesterDutiesForEpoch(ctx context.Context, target string, epoch int) (time.Duration, error) {
	body := strings.NewReader(`["1"]`)
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/duties/attester/%v", target, epoch), http.MethodPost, body, 200)
}

func getSyncCommitteeDutiesForEpoch(ctx context.Context, target string, epoch int) (time.Duration, error) {
	body := strings.NewReader(`["1"]`)
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/duties/sync/%v", target, epoch), http.MethodPost, body, 200)
}

func beaconHeadValidators(ctx context.Context, target string) (time.Duration, error) {
	body := strings.NewReader(`{"ids":["0xb6066945aa87a1e0e4b55e347d3a8a0ef7f0d9f7ef2c46abebadb25d7de176b83c88547e5f8644b659598063c845719a"]}`)
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/beacon/states/head/validators", target), http.MethodPost, body, 200)
}

func beaconGenesis(ctx context.Context, target string) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/beacon/genesis", target), http.MethodGet, nil, 200)
}

func prepBeaconProposer(ctx context.Context, target string) (time.Duration, error) {
	body := strings.NewReader(`[{"validator_index":"1725802","fee_recipient":"0x74b1C2f5788510c9ecA5f56D367B0a3D8a15a430"}]`)
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/prepare_beacon_proposer", target), http.MethodPost, body, 200)
}

func configSpec(ctx context.Context, target string) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/config/spec", target), http.MethodGet, nil, 200)
}

func nodeVersion(ctx context.Context, target string) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/node/version", target), http.MethodGet, nil, 200)
}

func getProposalDutiesForEpoch(ctx context.Context, target string, epoch int) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/duties/proposer/%v", target, epoch), http.MethodGet, nil, 200)
}

func getAttestationData(ctx context.Context, target string, slot int, committeeIndex int) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/attestation_data?slot=%v&committee_index=%v", target, slot, committeeIndex), http.MethodGet, nil, 200)
}

func submitAttestationObject(ctx context.Context, target string) (time.Duration, error) {
	body := strings.NewReader(`{{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}}`)
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/beacon/pool/attestations", target), http.MethodPost, body, 400)
}

func getAggregateAttestations(ctx context.Context, target string, slot int, attestationDataRoot string) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/aggregate_attestation?slot=%v&attestation_data_root=%v", target, slot, attestationDataRoot), http.MethodGet, nil, 404)
}

func aggregateAndProofs(ctx context.Context, target string) (time.Duration, error) {
	body := strings.NewReader(`[{"message":{"aggregator_index":"1","aggregate":{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}},"selection_proof":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}]`)
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/aggregate_and_proofs", target), http.MethodPost, body, 400)
}

func submitSyncCommittees(ctx context.Context, target string) (time.Duration, error) {
	body := strings.NewReader(`{{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}}`)
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/beacon/pool/sync_committees", target), http.MethodPost, body, 400)
}

func produceSyncCommitteeContribution(ctx context.Context, target string, slot int, subCommitteeIndex int, beaconBlockRoot string) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/sync_committee_contribution?slot=%v&subcommittee_index=%v&beacon_block_root=%v", target, slot, subCommitteeIndex, beaconBlockRoot), http.MethodGet, nil, 404)
}

func syncCommitteeSubscription(ctx context.Context, target string) (time.Duration, error) {
	body := strings.NewReader(`[{"message":{"aggregator_index":"1","aggregate":{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}},"selection_proof":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}]`)
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/sync_committee_subscriptions", target), http.MethodPost, body, 400)
}
