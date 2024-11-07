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
	LoadTest             bool
	LoadTestDuration     time.Duration
	SimulationValidators int
	SimulationFileDir    string
	SimulationDuration   int
	SimulationVerbose    bool
}

type testCaseBeacon func(context.Context, *testBeaconConfig, string) testResult

type simParams struct {
	TotalValidatorsCount         int
	AttestationValidatorsCount   int // attestation + aggregation
	ProposalValidatorsCount      int // attestation + aggregation + proposals
	SyncCommitteeValidatorsCount int // attestation + aggregation + proposals + sync committee
	RequestIntensity             RequestsIntensity
}

type SimulationValues struct {
	Endpoint string     `json:"endpoint,omitempty"`
	All      []Duration `json:"all,omitempty"`
	Min      Duration   `json:"min"`
	Max      Duration   `json:"max"`
	Median   Duration   `json:"median"`
	Avg      Duration   `json:"avg"`
}

type RequestsIntensity struct {
	AttestationDuty           time.Duration
	AggregatorDuty            time.Duration
	ProposalDuty              time.Duration
	SyncCommitteeSubmit       time.Duration
	SyncCommitteeContribution time.Duration
	SyncCommitteeSubscribe    time.Duration
}

type DutiesPerformed struct {
	Attestation   bool
	Aggregation   bool
	Proposal      bool
	SyncCommittee bool
}

type Simulation struct {
	GeneralClusterRequests SimulationCluster    `json:"general_cluster_requests"`
	ValidatorsRequests     SimulationValidators `json:"validators_requests"`
}

type SimulationValidators struct {
	Averaged      SimulationSingleValidator   `json:"averaged"`
	AllValidators []SimulationSingleValidator `json:"all_validators,omitempty"`
}

type SimulationSingleValidator struct {
	AttestationDuty     SimulationAttestation   `json:"attestation_duty"`
	AggregationDuty     SimulationAggregation   `json:"aggregation_duty"`
	ProposalDuty        SimulationProposal      `json:"proposal_duty"`
	SyncCommitteeDuties SimulationSyncCommittee `json:"sync_committee_duties"`
	SimulationValues
}

type SimulationAttestation struct {
	GetAttestationDataRequest SimulationValues `json:"get_attestation_data_request"`
	PostAttestationsRequest   SimulationValues `json:"post_attestations_request"`
	SimulationValues
}

type SimulationAggregation struct {
	GetAggregateAttestationRequest SimulationValues `json:"get_aggregate_attestation_request"`
	PostAggregateAndProofsRequest  SimulationValues `json:"post_aggregate_and_proofs_request"`
	SimulationValues
}

type SimulationProposal struct {
	ProduceBlockRequest        SimulationValues `json:"produce_block_request"`
	PublishBlindedBlockRequest SimulationValues `json:"publish_blinded_block_request"`
	SimulationValues
}

type SimulationSyncCommittee struct {
	MessageDuty                   SyncCommitteeMessageDuty      `json:"message_duty"`
	ContributionDuty              SyncCommitteeContributionDuty `json:"contribution_duty"`
	SubscribeSyncCommitteeRequest SimulationValues              `json:"subscribe_sync_committee_request"`
	SimulationValues
}

type SyncCommitteeContributionDuty struct {
	ProduceSyncCommitteeContributionRequest SimulationValues `json:"produce_sync_committee_contribution_request"`
	SubmitSyncCommitteeContributionRequest  SimulationValues `json:"submit_sync_committee_contribution_request"`
	SimulationValues
}

type SyncCommitteeMessageDuty struct {
	SubmitSyncCommitteeMessageRequest SimulationValues `json:"submit_sync_committee_message_request"`
}

type SimulationCluster struct {
	AttestationsForBlockRequest        SimulationValues `json:"attestations_for_block_request"`
	ProposalDutiesForEpochRequest      SimulationValues `json:"proposal_duties_for_epoch_request"`
	SyncingRequest                     SimulationValues `json:"syncing_request"`
	PeerCountRequest                   SimulationValues `json:"peer_count_request"`
	BeaconCommitteeSubscriptionRequest SimulationValues `json:"beacon_committee_subscription_request"`
	DutiesAttesterForEpochRequest      SimulationValues `json:"duties_attester_for_epoch_request"`
	DutiesSyncCommitteeForEpochRequest SimulationValues `json:"duties_sync_committee_for_epoch_request"`
	BeaconHeadValidatorsRequest        SimulationValues `json:"beacon_head_validators_request"`
	BeaconGenesisRequest               SimulationValues `json:"beacon_genesis_request"`
	PrepBeaconProposerRequest          SimulationValues `json:"prep_beacon_proposer_request"`
	ConfigSpecRequest                  SimulationValues `json:"config_spec_request"`
	NodeVersionRequest                 SimulationValues `json:"node_version_request"`
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
	cmd.Flags().BoolVar(&config.LoadTest, "load-test", false, "Enable load test, not advisable when testing towards external beacon nodes.")
	cmd.Flags().DurationVar(&config.LoadTestDuration, "load-test-duration", 5*time.Second, "Time to keep running the load tests in seconds. For each second a new continuous ping instance is spawned.")
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

		{name: "simulate1", order: 6}:     beaconSimulation1Test,
		{name: "simulate10", order: 7}:    beaconSimulation10Test,
		{name: "simulate100", order: 8}:   beaconSimulation100Test,
		{name: "simulate500", order: 9}:   beaconSimulation500Test,
		{name: "simulate1000", order: 10}: beaconSimulation1000Test,
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
	if !conf.LoadTest {
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

func beaconSimulation1Test(ctx context.Context, conf *testBeaconConfig, target string) testResult {
	testRes := testResult{Name: "BeaconSimulation1Validator"}
	if !conf.LoadTest {
		testRes.Verdict = testVerdictSkipped
		return testRes
	}

	params := simParams{
		TotalValidatorsCount:         1,
		AttestationValidatorsCount:   0,
		ProposalValidatorsCount:      0,
		SyncCommitteeValidatorsCount: 1,
		RequestIntensity: RequestsIntensity{
			AttestationDuty:           slotTime,
			AggregatorDuty:            slotTime * 2,
			ProposalDuty:              slotTime * 4,
			SyncCommitteeSubmit:       slotTime,
			SyncCommitteeContribution: slotTime * 4,
			SyncCommitteeSubscribe:    epochTime,
		},
	}

	return beaconSimulationTest(ctx, conf, target, testRes, params)
}

func beaconSimulation10Test(ctx context.Context, conf *testBeaconConfig, target string) testResult {
	testRes := testResult{Name: "BeaconSimulation10Validators"}
	if !conf.LoadTest {
		testRes.Verdict = testVerdictSkipped
		return testRes
	}

	params := simParams{
		TotalValidatorsCount:         10,
		AttestationValidatorsCount:   6,
		ProposalValidatorsCount:      3,
		SyncCommitteeValidatorsCount: 1,
		RequestIntensity: RequestsIntensity{
			AttestationDuty:           slotTime,
			AggregatorDuty:            slotTime * 2,
			ProposalDuty:              slotTime * 4,
			SyncCommitteeSubmit:       slotTime,
			SyncCommitteeContribution: slotTime * 4,
			SyncCommitteeSubscribe:    epochTime,
		},
	}

	return beaconSimulationTest(ctx, conf, target, testRes, params)
}

func beaconSimulation100Test(ctx context.Context, conf *testBeaconConfig, target string) testResult {
	testRes := testResult{Name: "BeaconSimulation100Validators"}
	if !conf.LoadTest {
		testRes.Verdict = testVerdictSkipped
		return testRes
	}

	params := simParams{
		TotalValidatorsCount:         100,
		AttestationValidatorsCount:   80,
		ProposalValidatorsCount:      18,
		SyncCommitteeValidatorsCount: 2,
		RequestIntensity: RequestsIntensity{
			AttestationDuty:           slotTime,
			AggregatorDuty:            slotTime * 2,
			ProposalDuty:              slotTime * 4,
			SyncCommitteeSubmit:       slotTime,
			SyncCommitteeContribution: slotTime * 4,
			SyncCommitteeSubscribe:    epochTime,
		},
	}

	return beaconSimulationTest(ctx, conf, target, testRes, params)
}

func beaconSimulation500Test(ctx context.Context, conf *testBeaconConfig, target string) testResult {
	testRes := testResult{Name: "BeaconSimulation500Validators"}
	if !conf.LoadTest {
		testRes.Verdict = testVerdictSkipped
		return testRes
	}

	params := simParams{
		TotalValidatorsCount:         500,
		AttestationValidatorsCount:   450,
		ProposalValidatorsCount:      45,
		SyncCommitteeValidatorsCount: 5,
		RequestIntensity: RequestsIntensity{
			AttestationDuty:           slotTime,
			AggregatorDuty:            slotTime * 2,
			ProposalDuty:              slotTime * 4,
			SyncCommitteeSubmit:       slotTime,
			SyncCommitteeContribution: slotTime * 4,
			SyncCommitteeSubscribe:    epochTime,
		},
	}

	return beaconSimulationTest(ctx, conf, target, testRes, params)
}

func beaconSimulation1000Test(ctx context.Context, conf *testBeaconConfig, target string) testResult {
	testRes := testResult{Name: "BeaconSimulation1000Validators"}
	if !conf.LoadTest {
		testRes.Verdict = testVerdictSkipped
		return testRes
	}

	params := simParams{
		TotalValidatorsCount:         1000,
		AttestationValidatorsCount:   930,
		ProposalValidatorsCount:      65,
		SyncCommitteeValidatorsCount: 5,
		RequestIntensity: RequestsIntensity{
			AttestationDuty:           slotTime,
			AggregatorDuty:            slotTime * 2,
			ProposalDuty:              slotTime * 4,
			SyncCommitteeSubmit:       slotTime,
			SyncCommitteeContribution: slotTime * 4,
			SyncCommitteeSubscribe:    epochTime,
		},
	}

	return beaconSimulationTest(ctx, conf, target, testRes, params)
}

func beaconSimulationTest(ctx context.Context, conf *testBeaconConfig, target string, testRes testResult, params simParams) testResult {
	duration := time.Duration(conf.SimulationDuration)*slotTime + time.Second
	var wg sync.WaitGroup

	log.Info(ctx, "Running beacon node simulation...",
		z.Any("validators_count", params.TotalValidatorsCount),
		z.Any("target", target),
		z.Any("duration_in_slots", conf.SimulationDuration),
		z.Any("slot_duration", slotTime),
	)

	// start general cluster requests
	simulationGeneralResCh := make(chan SimulationCluster, 1)
	var simulationGeneralRes SimulationCluster
	wg.Add(1)
	log.Info(ctx, "Starting general cluster requests...")
	go singleClusterSimulation(ctx, duration, target, simulationGeneralResCh, &wg)

	// start validator requests
	simulationResCh := make(chan SimulationSingleValidator, params.TotalValidatorsCount)
	simulationResAll := []SimulationSingleValidator{}

	log.Info(ctx, "Starting validators performing duties attestation, aggregation, proposal, sync committee...",
		z.Any("validators", params.SyncCommitteeValidatorsCount),
	)
	syncCommitteeValidatorsDuties := DutiesPerformed{Attestation: true, Aggregation: true, Proposal: true, SyncCommittee: true}
	for range params.SyncCommitteeValidatorsCount {
		wg.Add(1)
		go singleValidatorSimulation(ctx, duration, target, simulationResCh, params.RequestIntensity, syncCommitteeValidatorsDuties, &wg)
	}

	log.Info(ctx, "Starting validators performing duties attestation, aggregation, proposal...",
		z.Any("validators", params.ProposalValidatorsCount),
	)
	proposalValidatorsDuties := DutiesPerformed{Attestation: true, Aggregation: true, Proposal: true, SyncCommittee: false}
	for range params.ProposalValidatorsCount {
		wg.Add(1)
		go singleValidatorSimulation(ctx, duration, target, simulationResCh, params.RequestIntensity, proposalValidatorsDuties, &wg)
	}

	log.Info(ctx, "Starting validators performing duties attestation, aggregation...",
		z.Any("validators", params.AttestationValidatorsCount),
	)
	attesterValidatorsDuties := DutiesPerformed{Attestation: true, Aggregation: true, Proposal: false, SyncCommittee: false}
	for range params.AttestationValidatorsCount {
		wg.Add(1)
		go singleValidatorSimulation(ctx, duration, target, simulationResCh, params.RequestIntensity, attesterValidatorsDuties, &wg)
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
		GeneralClusterRequests: simulationGeneralRes,
		ValidatorsRequests: SimulationValidators{
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
	err = os.WriteFile(filepath.Join(conf.SimulationFileDir, fmt.Sprintf("%v-validators.json", params.TotalValidatorsCount)), simulationResAllJSON, 0o644) //nolint:gosec
	if err != nil {
		log.Error(ctx, "Failed to write file", err)
	}

	highestRTT := Duration{0}
	for _, sim := range simulationResAll {
		if sim.Max.Duration > highestRTT.Duration {
			highestRTT = sim.Max
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

	log.Info(ctx, "Validators simulation finished",
		z.Any("validators_count", params.TotalValidatorsCount),
		z.Any("target", target),
	)

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
	s.ValidatorsRequests.AllValidators = []SimulationSingleValidator{}

	s.ValidatorsRequests.Averaged.All = []Duration{}
	s.ValidatorsRequests.Averaged.AggregationDuty.All = []Duration{}
	s.ValidatorsRequests.Averaged.AggregationDuty.GetAggregateAttestationRequest.All = []Duration{}
	s.ValidatorsRequests.Averaged.AggregationDuty.PostAggregateAndProofsRequest.All = []Duration{}
	s.ValidatorsRequests.Averaged.AttestationDuty.All = []Duration{}
	s.ValidatorsRequests.Averaged.AttestationDuty.GetAttestationDataRequest.All = []Duration{}
	s.ValidatorsRequests.Averaged.AttestationDuty.PostAttestationsRequest.All = []Duration{}
	s.ValidatorsRequests.Averaged.ProposalDuty.All = []Duration{}
	s.ValidatorsRequests.Averaged.ProposalDuty.ProduceBlockRequest.All = []Duration{}
	s.ValidatorsRequests.Averaged.ProposalDuty.PublishBlindedBlockRequest.All = []Duration{}
	s.ValidatorsRequests.Averaged.SyncCommitteeDuties.All = []Duration{}
	s.ValidatorsRequests.Averaged.SyncCommitteeDuties.ContributionDuty.All = []Duration{}
	s.ValidatorsRequests.Averaged.SyncCommitteeDuties.ContributionDuty.ProduceSyncCommitteeContributionRequest.All = []Duration{}
	s.ValidatorsRequests.Averaged.SyncCommitteeDuties.ContributionDuty.SubmitSyncCommitteeContributionRequest.All = []Duration{}
	s.ValidatorsRequests.Averaged.SyncCommitteeDuties.MessageDuty.SubmitSyncCommitteeMessageRequest.All = []Duration{}
	s.ValidatorsRequests.Averaged.SyncCommitteeDuties.SubscribeSyncCommitteeRequest.All = []Duration{}

	s.GeneralClusterRequests.AttestationsForBlockRequest.All = []Duration{}
	s.GeneralClusterRequests.ProposalDutiesForEpochRequest.All = []Duration{}
	s.GeneralClusterRequests.SyncingRequest.All = []Duration{}
	s.GeneralClusterRequests.PeerCountRequest.All = []Duration{}
	s.GeneralClusterRequests.BeaconCommitteeSubscriptionRequest.All = []Duration{}
	s.GeneralClusterRequests.DutiesAttesterForEpochRequest.All = []Duration{}
	s.GeneralClusterRequests.DutiesSyncCommitteeForEpochRequest.All = []Duration{}
	s.GeneralClusterRequests.BeaconHeadValidatorsRequest.All = []Duration{}
	s.GeneralClusterRequests.BeaconGenesisRequest.All = []Duration{}
	s.GeneralClusterRequests.PrepBeaconProposerRequest.All = []Duration{}
	s.GeneralClusterRequests.ConfigSpecRequest.All = []Duration{}
	s.GeneralClusterRequests.NodeVersionRequest.All = []Duration{}

	return s
}

func singleClusterSimulation(ctx context.Context, simulationDuration time.Duration, target string, resultCh chan SimulationCluster, wg *sync.WaitGroup) {
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

	attestationsForBlockValues := generateSimulationValues(attestationsForBlockAll, "GET /eth/v1/beacon/blocks/{BLOCK}/attestations")
	proposalDutiesForEpochValues := generateSimulationValues(proposalDutiesForEpochAll, "GET /eth/v1/validator/duties/proposer/{EPOCH}")
	syncingValues := generateSimulationValues(syncingAll, "GET /eth/v1/node/syncing")
	peerCountValues := generateSimulationValues(peerCountAll, "GET /eth/v1/node/peer_count")
	beaconCommitteeSubValues := generateSimulationValues(beaconCommitteeSubAll, "POST /eth/v1/validator/beacon_committee_subscriptions")
	dutiesAttesterValues := generateSimulationValues(dutiesAttesterAll, "POST /eth/v1/validator/duties/attester/{EPOCH}")
	dutiesSyncCommitteeValues := generateSimulationValues(dutiesSyncCommitteeAll, "POST /eth/v1/validator/duties/sync/{EPOCH}")
	beaconHeadValidatorsValues := generateSimulationValues(beaconHeadValidatorsAll, "POST /eth/v1/beacon/states/head/validators")
	beaconGenesisValues := generateSimulationValues(beaconGenesisAll, "GET /eth/v1/beacon/genesis")
	prepBeaconProposerValues := generateSimulationValues(prepBeaconProposerAll, "POST /eth/v1/validator/prepare_beacon_proposer")
	configSpecValues := generateSimulationValues(configSpecAll, "GET /eth/v1/config/spec")
	nodeVersionValues := generateSimulationValues(nodeVersionAll, "GET /eth/v1/node/version")

	generalResults := SimulationCluster{
		AttestationsForBlockRequest:        attestationsForBlockValues,
		ProposalDutiesForEpochRequest:      proposalDutiesForEpochValues,
		SyncingRequest:                     syncingValues,
		PeerCountRequest:                   peerCountValues,
		BeaconCommitteeSubscriptionRequest: beaconCommitteeSubValues,
		DutiesAttesterForEpochRequest:      dutiesAttesterValues,
		DutiesSyncCommitteeForEpochRequest: dutiesSyncCommitteeValues,
		BeaconHeadValidatorsRequest:        beaconHeadValidatorsValues,
		BeaconGenesisRequest:               beaconGenesisValues,
		PrepBeaconProposerRequest:          prepBeaconProposerValues,
		ConfigSpecRequest:                  configSpecValues,
		NodeVersionRequest:                 nodeVersionValues,
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
			if err != nil && !errors.Is(err, context.Canceled) {
				log.Error(ctx, "Unexpected getAttestationsForBlock failure", err)
			}
			attestationsForBlockCh <- attestationsResult
			submitResult, err := getProposalDutiesForEpoch(ctx, target, epoch)
			if err != nil && !errors.Is(err, context.Canceled) {
				log.Error(ctx, "Unexpected getProposalDutiesForEpoch failure", err)
			}
			proposalDutiesForEpochCh <- submitResult
			// requests executed at the first slot of the epoch
			if slot%slotsInEpoch == 0 {
				dutiesAttesterResult, err := getAttesterDutiesForEpoch(ctx, target, epoch)
				if err != nil && !errors.Is(err, context.Canceled) {
					log.Error(ctx, "Unexpected getAttesterDutiesForEpoch failure", err)
				}
				dutiesAttesterCh <- dutiesAttesterResult

				dutiesSyncCommitteeResult, err := getSyncCommitteeDutiesForEpoch(ctx, target, epoch)
				if err != nil && !errors.Is(err, context.Canceled) {
					log.Error(ctx, "Unexpected getSyncCommitteeDutiesForEpoch failure", err)
				}
				dutiesSyncCommitteeCh <- dutiesSyncCommitteeResult

				beaconHeadValidatorsResult, err := beaconHeadValidators(ctx, target)
				if err != nil && !errors.Is(err, context.Canceled) {
					log.Error(ctx, "Unexpected beaconHeadValidators failure", err)
				}
				beaconHeadValidatorsCh <- beaconHeadValidatorsResult

				beaconGenesisResult, err := beaconGenesis(ctx, target)
				if err != nil && !errors.Is(err, context.Canceled) {
					log.Error(ctx, "Unexpected beaconGenesis failure", err)
				}
				beaconGenesisCh <- beaconGenesisResult

				prepBeaconProposerResult, err := prepBeaconProposer(ctx, target)
				if err != nil && !errors.Is(err, context.Canceled) {
					log.Error(ctx, "Unexpected prepBeaconProposer failure", err)
				}
				prepBeaconProposerCh <- prepBeaconProposerResult

				configSpecResult, err := configSpec(ctx, target)
				if err != nil && !errors.Is(err, context.Canceled) {
					log.Error(ctx, "Unexpected configSpec failure", err)
				}
				configSpecCh <- configSpecResult

				nodeVersionResult, err := nodeVersion(ctx, target)
				if err != nil && !errors.Is(err, context.Canceled) {
					log.Error(ctx, "Unexpected nodeVersion failure", err)
				}
				nodeVersionCh <- nodeVersionResult
			}
			// requests executed at the last but one slot of the epoch
			if slot%slotsInEpoch == slotsInEpoch-2 {
				dutiesAttesterResult, err := getAttesterDutiesForEpoch(ctx, target, epoch)
				if err != nil && !errors.Is(err, context.Canceled) {
					log.Error(ctx, "Unexpected getAttesterDutiesForEpoch failure", err)
				}
				dutiesAttesterCh <- dutiesAttesterResult
			}
			// requests executed at the last slot of the epoch
			if slot%slotsInEpoch == slotsInEpoch-1 {
				dutiesAttesterResult, err := getAttesterDutiesForEpoch(ctx, target, epoch)
				if err != nil && !errors.Is(err, context.Canceled) {
					log.Error(ctx, "Unexpected getAttesterDutiesForEpoch failure", err)
				}
				dutiesAttesterCh <- dutiesAttesterResult

				dutiesSyncCommitteeResult, err := getSyncCommitteeDutiesForEpoch(ctx, target, epoch)
				if err != nil && !errors.Is(err, context.Canceled) {
					log.Error(ctx, "Unexpected getSyncCommitteeDutiesForEpoch failure", err)
				}
				dutiesSyncCommitteeCh <- dutiesSyncCommitteeResult

				dutiesSyncCommitteeResultFuture, err := getSyncCommitteeDutiesForEpoch(ctx, target, epoch+256)
				if err != nil && !errors.Is(err, context.Canceled) {
					log.Error(ctx, "Unexpected getSyncCommitteeDutiesForEpoch for the future epoch failure", err)
				}
				dutiesSyncCommitteeCh <- dutiesSyncCommitteeResultFuture
			}
		case <-ticker12Slots.C:
			beaconCommitteeSubResult, err := beaconCommitteeSub(ctx, target)
			if err != nil && !errors.Is(err, context.Canceled) {
				log.Error(ctx, "Unexpected beaconCommitteeSub failure", err)
			}
			beaconCommitteeSubCh <- beaconCommitteeSubResult
		case <-ticker10Sec.C:
			getSyncingResult, err := getSyncing(ctx, target)
			if err != nil && !errors.Is(err, context.Canceled) {
				log.Error(ctx, "Unexpected getSyncing failure", err)
			}
			syncingCh <- getSyncingResult
		case <-tickerMinute.C:
			peerCountResult, err := getPeerCount(ctx, target)
			if err != nil && !errors.Is(err, context.Canceled) {
				log.Error(ctx, "Unexpected getPeerCount failure", err)
			}
			peerCountCh <- peerCountResult
		case <-pingCtx.Done():
		}
	}
}

func singleValidatorSimulation(ctx context.Context, simulationDuration time.Duration, target string, resultCh chan SimulationSingleValidator, intensity RequestsIntensity, dutiesPerformed DutiesPerformed, wg *sync.WaitGroup) {
	defer wg.Done()
	// attestations
	getAttestationDataCh := make(chan time.Duration)
	getAttestationDataAll := []time.Duration{}
	submitAttestationObjectCh := make(chan time.Duration)
	submitAttestationObjectAll := []time.Duration{}
	if dutiesPerformed.Attestation {
		go attestationDuty(ctx, target, simulationDuration, intensity.AttestationDuty, getAttestationDataCh, submitAttestationObjectCh)
	}

	// aggregations
	getAggregateAttestationsCh := make(chan time.Duration)
	getAggregateAttestationsAll := []time.Duration{}
	submitAggregateAndProofsCh := make(chan time.Duration)
	submitAggregateAndProofsAll := []time.Duration{}
	if dutiesPerformed.Aggregation {
		go aggregationDuty(ctx, target, simulationDuration, intensity.AggregatorDuty, getAggregateAttestationsCh, submitAggregateAndProofsCh)
	}

	// proposals
	produceBlockCh := make(chan time.Duration)
	produceBlockAll := []time.Duration{}
	publishBlindedBlockCh := make(chan time.Duration)
	publishBlindedBlockAll := []time.Duration{}
	if dutiesPerformed.Proposal {
		go proposalDuty(ctx, target, simulationDuration, intensity.ProposalDuty, produceBlockCh, publishBlindedBlockCh)
	}

	// sync_committee
	syncCommitteeSubscriptionCh := make(chan time.Duration)
	syncCommitteeSubscriptionAll := []time.Duration{}
	submitSyncCommitteeMessageCh := make(chan time.Duration)
	submitSyncCommitteeMessageAll := []time.Duration{}
	produceSyncCommitteeContributionCh := make(chan time.Duration)
	produceSyncCommitteeContributionAll := []time.Duration{}
	submitSyncCommitteeContributionCh := make(chan time.Duration)
	submitSyncCommitteeContributionAll := []time.Duration{}
	if dutiesPerformed.SyncCommittee {
		go syncCommitteeDuties(ctx, target,
			simulationDuration, intensity.SyncCommitteeSubmit, intensity.SyncCommitteeSubscribe, intensity.SyncCommitteeContribution,
			submitSyncCommitteeMessageCh, produceSyncCommitteeContributionCh, syncCommitteeSubscriptionCh, submitSyncCommitteeContributionCh)
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
		case result, ok := <-submitSyncCommitteeMessageCh:
			if !ok {
				finished = true
				continue
			}
			submitSyncCommitteeMessageAll = append(submitSyncCommitteeMessageAll, result)
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
		case result, ok := <-submitSyncCommitteeContributionCh:

			if !ok {
				finished = true
				continue
			}
			submitSyncCommitteeContributionAll = append(submitSyncCommitteeContributionAll, result)
		}
	}

	var allRequests []time.Duration

	// attestation results grouping
	var attestationResult SimulationAttestation
	if dutiesPerformed.Attestation {
		getSimulationValues := generateSimulationValues(getAttestationDataAll, "GET /eth/v1/validator/attestation_data")
		submitSimulationValues := generateSimulationValues(submitAttestationObjectAll, "POST /eth/v1/beacon/pool/attestations")

		cumulativeAttestation := []time.Duration{}
		for i := range min(len(getAttestationDataAll), len(submitAttestationObjectAll)) {
			cumulativeAttestation = append(cumulativeAttestation, getAttestationDataAll[i]+submitAttestationObjectAll[i])
		}
		cumulativeSimulationValues := generateSimulationValues(cumulativeAttestation, "")
		allRequests = append(allRequests, cumulativeAttestation...)

		attestationResult = SimulationAttestation{
			GetAttestationDataRequest: getSimulationValues,
			PostAttestationsRequest:   submitSimulationValues,
			SimulationValues:          cumulativeSimulationValues,
		}
	}

	// aggregation results grouping
	var aggregationResults SimulationAggregation
	if dutiesPerformed.Aggregation {
		getAggregateSimulationValues := generateSimulationValues(getAggregateAttestationsAll, "GET /eth/v1/validator/aggregate_attestation")
		submitAggregateSimulationValues := generateSimulationValues(submitAggregateAndProofsAll, "POST /eth/v1/validator/aggregate_and_proofs")

		cumulativeAggregations := []time.Duration{}
		for i := range min(len(getAggregateAttestationsAll), len(submitAggregateAndProofsAll)) {
			cumulativeAggregations = append(cumulativeAggregations, getAggregateAttestationsAll[i]+submitAggregateAndProofsAll[i])
		}
		cumulativeAggregationsSimulationValues := generateSimulationValues(cumulativeAggregations, "")
		allRequests = append(allRequests, cumulativeAggregations...)

		aggregationResults = SimulationAggregation{
			GetAggregateAttestationRequest: getAggregateSimulationValues,
			PostAggregateAndProofsRequest:  submitAggregateSimulationValues,
			SimulationValues:               cumulativeAggregationsSimulationValues,
		}
	}

	// proposal results grouping
	var proposalResults SimulationProposal
	if dutiesPerformed.Proposal {
		produceBlockValues := generateSimulationValues(produceBlockAll, "GET /eth/v3/validator/blocks/{SLOT}")
		publishBlindedBlockValues := generateSimulationValues(publishBlindedBlockAll, "POST /eth/v2/beacon/blinded")

		cumulativeProposals := []time.Duration{}
		for i := range min(len(produceBlockAll), len(publishBlindedBlockAll)) {
			cumulativeProposals = append(cumulativeProposals, produceBlockAll[i]+publishBlindedBlockAll[i])
		}
		cumulativeProposalsSimulationValues := generateSimulationValues(cumulativeProposals, "")
		allRequests = append(allRequests, cumulativeProposals...)

		proposalResults = SimulationProposal{
			ProduceBlockRequest:        produceBlockValues,
			PublishBlindedBlockRequest: publishBlindedBlockValues,
			SimulationValues:           cumulativeProposalsSimulationValues,
		}
	}

	// sync committee results grouping
	var syncCommitteeResults SimulationSyncCommittee
	if dutiesPerformed.SyncCommittee {
		syncCommitteeAll := []time.Duration{}
		syncCommitteeSubscriptionValues := generateSimulationValues(syncCommitteeSubscriptionAll, "POST /eth/v1/validator/sync_committee_subscriptions")
		syncCommitteeAll = append(syncCommitteeAll, syncCommitteeSubscriptionAll...)
		allRequests = append(allRequests, syncCommitteeSubscriptionAll...)

		submitSyncCommitteeMessageValues := generateSimulationValues(submitSyncCommitteeMessageAll, "POST /eth/v1/beacon/pool/sync_committees")
		syncCommitteeAll = append(syncCommitteeAll, submitSyncCommitteeMessageAll...)
		allRequests = append(allRequests, submitSyncCommitteeMessageAll...)

		produceSyncCommitteeContributionValues := generateSimulationValues(produceSyncCommitteeContributionAll, "GET /eth/v1/validator/sync_committee_contribution")
		submitSyncCommitteeContributionValues := generateSimulationValues(submitSyncCommitteeContributionAll, "POST /eth/v1/validator/contribution_and_proofs")

		syncCommitteeContributionAll := []time.Duration{}
		for i := range min(len(produceSyncCommitteeContributionAll), len(submitSyncCommitteeContributionAll)) {
			syncCommitteeContributionAll = append(syncCommitteeContributionAll, produceSyncCommitteeContributionAll[i]+submitSyncCommitteeContributionAll[i])
		}
		syncCommitteeContributionValues := generateSimulationValues(syncCommitteeContributionAll, "")
		syncCommitteeAll = append(syncCommitteeAll, syncCommitteeContributionAll...)
		allRequests = append(allRequests, syncCommitteeContributionAll...)

		cumulativeSyncCommitteesSimulationValues := generateSimulationValues(syncCommitteeAll, "")

		syncCommitteeResults = SimulationSyncCommittee{
			MessageDuty: SyncCommitteeMessageDuty{
				SubmitSyncCommitteeMessageRequest: submitSyncCommitteeMessageValues,
			},
			ContributionDuty: SyncCommitteeContributionDuty{
				ProduceSyncCommitteeContributionRequest: produceSyncCommitteeContributionValues,
				SubmitSyncCommitteeContributionRequest:  submitSyncCommitteeContributionValues,
				SimulationValues:                        syncCommitteeContributionValues,
			},
			SubscribeSyncCommitteeRequest: syncCommitteeSubscriptionValues,
			SimulationValues:              cumulativeSyncCommitteesSimulationValues,
		}
	}

	allResult := generateSimulationValues(allRequests, "")

	resultCh <- SimulationSingleValidator{
		AttestationDuty:     attestationResult,
		AggregationDuty:     aggregationResults,
		ProposalDuty:        proposalResults,
		SyncCommitteeDuties: syncCommitteeResults,
		SimulationValues:    allResult,
	}
}

func mapDurationToTime(dur []Duration) []time.Duration {
	result := make([]time.Duration, len(dur))
	for i, e := range dur {
		result[i] = e.Duration
	}

	return result
}

func generateSimulationValues(s []time.Duration, endpoint string) SimulationValues {
	if len(s) == 0 {
		return SimulationValues{
			Endpoint: endpoint,
			All:      []Duration{},
			Min:      Duration{0},
			Max:      Duration{0},
			Median:   Duration{0},
			Avg:      Duration{0},
		}
	}

	sorted := make([]time.Duration, len(s))
	copy(sorted, s)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})
	minVal := sorted[0]
	maxVal := sorted[len(s)-1]
	medianVal := sorted[len(s)/2]
	var sum time.Duration
	all := []Duration{}
	for _, t := range s {
		sum += t
		all = append(all, Duration{t})
	}
	avgVal := time.Duration(int(sum.Nanoseconds()) / len(s))

	return SimulationValues{
		Endpoint: endpoint,
		All:      all,
		Min:      Duration{minVal},
		Max:      Duration{maxVal},
		Median:   Duration{medianVal},
		Avg:      Duration{avgVal},
	}
}

func averageValidatorsResult(s []SimulationSingleValidator) SimulationSingleValidator {
	if len(s) == 0 {
		return SimulationSingleValidator{}
	}

	var attestation, attestationGetDuties, attestationPostData,
		aggregation, aggregationGetAggregationAttestations, aggregationSubmitAggregateAndProofs,
		proposal, proposalProduceBlock, proposalPublishBlindedBlock,
		syncCommittee, syncCommitteeSubmitMessage, syncCommitteeProduceContribution, syncCommitteeSubmitContribution, syncCommitteeContribution, syncCommitteeSusbscription,
		all []time.Duration

	for _, sim := range s {
		attestationGetDuties = append(attestationGetDuties, mapDurationToTime(sim.AttestationDuty.GetAttestationDataRequest.All)...)
		attestationPostData = append(attestationPostData, mapDurationToTime(sim.AttestationDuty.PostAttestationsRequest.All)...)
		attestation = append(attestation, mapDurationToTime(sim.AttestationDuty.All)...)
		aggregationGetAggregationAttestations = append(aggregationGetAggregationAttestations, mapDurationToTime(sim.AggregationDuty.GetAggregateAttestationRequest.All)...)
		aggregationSubmitAggregateAndProofs = append(aggregationSubmitAggregateAndProofs, mapDurationToTime(sim.AggregationDuty.PostAggregateAndProofsRequest.All)...)
		aggregation = append(aggregation, mapDurationToTime(sim.AggregationDuty.All)...)
		proposalProduceBlock = append(proposalProduceBlock, mapDurationToTime(sim.ProposalDuty.ProduceBlockRequest.All)...)
		proposalPublishBlindedBlock = append(proposalPublishBlindedBlock, mapDurationToTime(sim.ProposalDuty.PublishBlindedBlockRequest.All)...)
		proposal = append(proposal, mapDurationToTime(sim.ProposalDuty.All)...)
		syncCommitteeSubmitMessage = append(syncCommitteeSubmitMessage, mapDurationToTime(sim.SyncCommitteeDuties.MessageDuty.SubmitSyncCommitteeMessageRequest.All)...)
		syncCommitteeProduceContribution = append(syncCommitteeProduceContribution, mapDurationToTime(sim.SyncCommitteeDuties.ContributionDuty.ProduceSyncCommitteeContributionRequest.All)...)
		syncCommitteeSubmitContribution = append(syncCommitteeSubmitContribution, mapDurationToTime(sim.SyncCommitteeDuties.ContributionDuty.SubmitSyncCommitteeContributionRequest.All)...)
		syncCommitteeContribution = append(syncCommitteeContribution, mapDurationToTime(sim.SyncCommitteeDuties.ContributionDuty.All)...)
		syncCommitteeSusbscription = append(syncCommitteeSusbscription, mapDurationToTime(sim.SyncCommitteeDuties.SubscribeSyncCommitteeRequest.All)...)
		syncCommittee = append(syncCommittee, mapDurationToTime(sim.SyncCommitteeDuties.All)...)
		all = append(all, mapDurationToTime(sim.All)...)
	}

	return SimulationSingleValidator{
		AttestationDuty: SimulationAttestation{
			GetAttestationDataRequest: generateSimulationValues(attestationGetDuties, "GET /eth/v1/validator/attestation_data"),
			PostAttestationsRequest:   generateSimulationValues(attestationPostData, "POST /eth/v1/beacon/pool/attestations"),
			SimulationValues:          generateSimulationValues(attestation, ""),
		},
		AggregationDuty: SimulationAggregation{
			GetAggregateAttestationRequest: generateSimulationValues(aggregationGetAggregationAttestations, "GET /eth/v1/validator/aggregate_attestation"),
			PostAggregateAndProofsRequest:  generateSimulationValues(aggregationSubmitAggregateAndProofs, "POST /eth/v1/validator/aggregate_and_proofs"),
			SimulationValues:               generateSimulationValues(aggregation, ""),
		},
		ProposalDuty: SimulationProposal{
			ProduceBlockRequest:        generateSimulationValues(proposalProduceBlock, "GET /eth/v3/validator/blocks/{SLOT}"),
			PublishBlindedBlockRequest: generateSimulationValues(proposalPublishBlindedBlock, "POST /eth/v2/beacon/blinded"),
			SimulationValues:           generateSimulationValues(proposal, ""),
		},
		SyncCommitteeDuties: SimulationSyncCommittee{
			MessageDuty: SyncCommitteeMessageDuty{
				SubmitSyncCommitteeMessageRequest: generateSimulationValues(syncCommitteeSubmitMessage, "POST /eth/v1/beacon/pool/sync_committees"),
			},
			ContributionDuty: SyncCommitteeContributionDuty{
				ProduceSyncCommitteeContributionRequest: generateSimulationValues(syncCommitteeProduceContribution, "GET /eth/v1/validator/sync_committee_contribution"),
				SubmitSyncCommitteeContributionRequest:  generateSimulationValues(syncCommitteeSubmitContribution, "POST /eth/v1/validator/contribution_and_proofs"),
				SimulationValues:                        generateSimulationValues(syncCommitteeContribution, ""),
			},
			SubscribeSyncCommitteeRequest: generateSimulationValues(syncCommitteeSusbscription, "POST /eth/v1/validator/sync_committee_subscriptions"),
			SimulationValues:              generateSimulationValues(syncCommittee, ""),
		},
		SimulationValues: generateSimulationValues(all, ""),
	}
}

func aggregationDuty(ctx context.Context, target string, simulationDuration time.Duration, tickTime time.Duration, getAggregateAttestationsCh chan time.Duration, submitAggregateAndProofsCh chan time.Duration) {
	defer close(getAggregateAttestationsCh)
	defer close(submitAggregateAndProofsCh)
	pingCtx, cancel := context.WithTimeout(ctx, simulationDuration)
	defer cancel()
	ticker := time.NewTicker(tickTime)
	defer ticker.Stop()
	slot, err := getCurrentSlot(ctx, target)
	if err != nil {
		log.Error(ctx, "Failed to get current slot", err)
		slot = 1
	}
	for pingCtx.Err() == nil {
		// TODO: use real attestation data root
		getResult, err := getAggregateAttestations(ctx, target, slot, "0x87db5c50a4586fa37662cf332382d56a0eeea688a7d7311a42735683dfdcbfa4")
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Error(ctx, "Unexpected getAggregateAttestations failure", err)
		}
		submitResult, err := postAggregateAndProofs(ctx, target)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Error(ctx, "Unexpected aggregateAndProofs failure", err)
		}
		getAggregateAttestationsCh <- getResult
		submitAggregateAndProofsCh <- submitResult
		select {
		case <-pingCtx.Done():
		case <-ticker.C:
			slot += int(tickTime.Seconds()) / int(slotTime.Seconds())
		}
	}
}

func proposalDuty(ctx context.Context, target string, simulationDuration time.Duration, tickTime time.Duration, produceBlockCh chan time.Duration, publishBlindedBlockCh chan time.Duration) {
	defer close(produceBlockCh)
	defer close(publishBlindedBlockCh)
	pingCtx, cancel := context.WithTimeout(ctx, simulationDuration)
	defer cancel()
	// randomize duty execution between tickTimeSlot + [0, tickTimeSlot)
	time.Sleep(slotTime * time.Duration(rand.Intn(int((tickTime / slotTime))))) //nolint:gosec // weak generator is not an issue here
	ticker := time.NewTicker(tickTime)
	defer ticker.Stop()
	slot, err := getCurrentSlot(ctx, target)
	if err != nil {
		log.Error(ctx, "Failed to get current slot", err)
		slot = 1
	}
	for pingCtx.Err() == nil {
		produceResult, err := produceBlock(ctx, target, slot, "0x1fe79e4193450abda94aec753895cfb2aac2c2a930b6bab00fbb27ef6f4a69f4400ad67b5255b91837982b4c511ae1d94eae1cf169e20c11bd417c1fffdb1f99f4e13e2de68f3b5e73f1de677d73cd43e44bf9b133a79caf8e5fad06738e1b0c")
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Error(ctx, "Unexpected produceBlock failure", err)
		}
		publishResult, err := publishBlindedBlock(ctx, target)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Error(ctx, "Unexpected publishBlindedBlock failure", err)
		}
		produceBlockCh <- produceResult
		publishBlindedBlockCh <- publishResult
		select {
		case <-pingCtx.Done():
		case <-ticker.C:
			slot += int(tickTime.Seconds())/int(slotTime.Seconds()) + 1 // produce block for the next slot, as the current one might have already been proposed
		}
	}
}

func attestationDuty(ctx context.Context, target string, simulationDuration time.Duration, tickTime time.Duration, getAttestationDataCh chan time.Duration, submitAttestationObjectCh chan time.Duration) {
	defer close(getAttestationDataCh)
	defer close(submitAttestationObjectCh)
	pingCtx, cancel := context.WithTimeout(ctx, simulationDuration)
	defer cancel()
	// randomize duty execution between tickTimeSlot + [0, tickTimeSlot)
	time.Sleep(slotTime * time.Duration(rand.Intn(int((tickTime / slotTime)))) * time.Second) //nolint:gosec,durationcheck // weak generator is not an issue here, duration multiplication is fine
	ticker := time.NewTicker(tickTime)
	defer ticker.Stop()
	slot, err := getCurrentSlot(ctx, target)
	if err != nil {
		log.Error(ctx, "Failed to get current slot", err)
		slot = 1
	}
	for pingCtx.Err() == nil {
		getResult, err := getAttestationData(ctx, target, slot, rand.Intn(committeeSizePerSlot)) //nolint:gosec // weak generator is not an issue here
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Error(ctx, "Unexpected getAttestationData failure", err)
		}
		getAttestationDataCh <- getResult

		submitResult, err := submitAttestationObject(ctx, target)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Error(ctx, "Unexpected submitAttestationObject failure", err)
		}
		submitAttestationObjectCh <- submitResult

		select {
		case <-pingCtx.Done():
		case <-ticker.C:
			slot += int(tickTime.Seconds()) / int(slotTime.Seconds())
		}
	}
}

func syncCommitteeDuties(
	ctx context.Context, target string,
	simulationDuration time.Duration, tickTimeSubmit time.Duration, tickTimeSubscribe time.Duration, tickTimeContribution time.Duration,
	submitSyncCommitteesCh chan time.Duration, produceSyncCommitteeContributionCh chan time.Duration, syncCommitteeSubscriptionCh chan time.Duration, syncCommitteeContributionCh chan time.Duration,
) {
	go syncCommitteeContributionDuty(ctx, target, simulationDuration, tickTimeContribution, produceSyncCommitteeContributionCh, syncCommitteeContributionCh)
	go syncCommitteeMessageDuty(ctx, target, simulationDuration, tickTimeSubmit, submitSyncCommitteesCh)

	defer close(syncCommitteeSubscriptionCh)
	pingCtx, cancel := context.WithTimeout(ctx, simulationDuration)
	defer cancel()

	// randomize duty execution between tickTimeSlot + [0, tickTimeSlot)
	time.Sleep(slotTime * time.Duration(rand.Intn(int((tickTimeSubscribe / slotTime)))) * time.Second) //nolint:gosec,durationcheck // weak generator is not an issue here, duration multiplication is fine
	ticker := time.NewTicker(tickTimeSubscribe)
	defer ticker.Stop()

	for pingCtx.Err() == nil {
		subscribeResult, err := syncCommitteeSubscription(ctx, target)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Error(ctx, "Unexpected syncCommitteeSubscription failure", err)
		}
		syncCommitteeSubscriptionCh <- subscribeResult

		select {
		case <-pingCtx.Done():
		case <-ticker.C:
		}
	}
}

func syncCommitteeContributionDuty(ctx context.Context, target string, simulationDuration time.Duration, tickTime time.Duration, produceSyncCommitteeContributionCh chan time.Duration, syncCommitteeContributionCh chan time.Duration) {
	defer close(produceSyncCommitteeContributionCh)
	defer close(syncCommitteeContributionCh)
	pingCtx, cancel := context.WithTimeout(ctx, simulationDuration)
	defer cancel()

	// randomize duty execution between tickTimeSlot + [0, tickTimeSlot)
	time.Sleep(slotTime * time.Duration(rand.Intn(int((tickTime / slotTime)))) * time.Second) //nolint:gosec,durationcheck // weak generator is not an issue here, duration multiplication is fine
	ticker := time.NewTicker(tickTime)
	defer ticker.Stop()

	slot, err := getCurrentSlot(ctx, target)
	if err != nil {
		log.Error(ctx, "Failed to get current slot", err)
		slot = 1
	}
	for pingCtx.Err() == nil {
		produceResult, err := produceSyncCommitteeContribution(ctx, target, slot, rand.Intn(subCommitteeSize), "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2") //nolint:gosec // weak generator is not an issue here
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Error(ctx, "Unexpected produceSyncCommitteeContribution failure", err)
		}
		produceSyncCommitteeContributionCh <- produceResult
		contributeResult, err := submitSyncCommitteeContribution(ctx, target)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Error(ctx, "Unexpected submitSyncCommitteeContribution failure", err)
		}
		syncCommitteeContributionCh <- contributeResult
		select {
		case <-pingCtx.Done():
		case <-ticker.C:
			slot += int(tickTime.Seconds()) / int(slotTime.Seconds())
		}
	}
}

func syncCommitteeMessageDuty(ctx context.Context, target string, simulationDuration time.Duration, tickTime time.Duration, submitSyncCommitteesCh chan time.Duration) {
	defer close(submitSyncCommitteesCh)
	pingCtx, cancel := context.WithTimeout(ctx, simulationDuration)
	defer cancel()

	// randomize duty execution between tickTimeSlot + [0, tickTimeSlot)
	time.Sleep(slotTime * time.Duration(rand.Intn(int((tickTime / slotTime)))) * time.Second) //nolint:gosec,durationcheck // weak generator is not an issue here, duration multiplication is fine
	ticker := time.NewTicker(tickTime)
	defer ticker.Stop()

	for pingCtx.Err() == nil {
		submitResult, err := submitSyncCommittee(ctx, target)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Error(ctx, "Unexpected submitSyncCommittee failure", err)
		}
		submitSyncCommitteesCh <- submitResult
		select {
		case <-pingCtx.Done():
		case <-ticker.C:
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

// cluster requests
func getAttestationsForBlock(ctx context.Context, target string, block int) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/beacon/blocks/%v/attestations", target, block), http.MethodGet, nil, 200)
}

func getProposalDutiesForEpoch(ctx context.Context, target string, epoch int) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/duties/proposer/%v", target, epoch), http.MethodGet, nil, 200)
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

// attestation duty requests
func getAttestationData(ctx context.Context, target string, slot int, committeeIndex int) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/attestation_data?slot=%v&committee_index=%v", target, slot, committeeIndex), http.MethodGet, nil, 200)
}

func submitAttestationObject(ctx context.Context, target string) (time.Duration, error) {
	body := strings.NewReader(`{{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}}`)
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/beacon/pool/attestations", target), http.MethodPost, body, 400)
}

// aggregation duty requests
func getAggregateAttestations(ctx context.Context, target string, slot int, attestationDataRoot string) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/aggregate_attestation?slot=%v&attestation_data_root=%v", target, slot, attestationDataRoot), http.MethodGet, nil, 404)
}

func postAggregateAndProofs(ctx context.Context, target string) (time.Duration, error) {
	body := strings.NewReader(`[{"message":{"aggregator_index":"1","aggregate":{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}},"selection_proof":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}]`)
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/aggregate_and_proofs", target), http.MethodPost, body, 400)
}

// proposal duty requests
func produceBlock(ctx context.Context, target string, slot int, randaoReveal string) (time.Duration, error) {
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v3/validator/blocks/%v?randao_reveal=%v", target, slot, randaoReveal), http.MethodGet, nil, 200)
}

func publishBlindedBlock(ctx context.Context, target string) (time.Duration, error) {
	body := strings.NewReader(`{"message":{"slot":"2872079","proposer_index":"1725813","parent_root":"0x05bea9b8e9cc28c4efa5586b4efac20b7a42c3112dbe144fb552b37ded249abd","state_root":"0x0138e6e8e956218aa534597a450a93c2c98f07da207077b4be05742279688da2","body":{"randao_reveal":"0x9880dad5a0e900906a1355da0697821af687b4c2cd861cd219f2d779c50a47d3c0335c08d840c86c167986ae0aaf50070b708fe93a83f66c99a4f931f9a520aebb0f5b11ca202c3d76343e30e49f43c0479e850af0e410333f7c59c4d37fa95a","eth1_data":{"deposit_root":"0x7dbea1a0af14d774da92d94a88d3bb1ae7abad16374da4db2c71dd086c84029e","deposit_count":"452100","block_hash":"0xc4bf450c9e362dcb2b50e76b45938c78d455acd1e1aec4e1ce4338ec023cd32a"},"graffiti":"0x636861726f6e2f76312e312e302d613139336638340000000000000000000000","proposer_slashings":[],"attester_slashings":[],"attestations":[{"aggregation_bits":"0xdbedbfa74eccaf3d7ef570bfdbbf84b4dffc5beede1c1f8b59feb8b3f2fbabdbdef3ceeb7b3dfdeeef8efcbdcd7bebbeff7adfff5ae3bf66bc5613feffef3deb987f7e7fff87ed6f8bbd1fffa57f1677efff646f0d3bd79fffdc5dfd78df6cf79fb7febff5dfdefb8e03","data":{"slot":"2872060","index":"12","beacon_block_root":"0x310506169f7f92dcd2bf00e8b4c2daac999566929395120fbbf4edd222e003eb","source":{"epoch":"89750","root":"0xcdb449d69e3e2d22378bfc2299ee1e9aeb1b2d15066022e854759dda73d1e219"},"target":{"epoch":"89751","root":"0x4ad0882f7adbb735c56b0b3f09d8e45dbd79db9528110f7117ec067f3a19eb0e"}},"signature":"0xa9d91d6cbc669ffcc8ba2435c633e0ec0eebecaa3acdcaa1454282ece1f816e8b853f00ba67ec1244703221efae4c834012819ca7b199354669f24ba8ab1c769f072c9f46b803082eac32e3611cd323eeb5b17fcd6201b41f3063834ff26ef53"}],"deposits":[],"voluntary_exits":[],"sync_aggregate":{"sync_committee_bits":"0xf9ff3ff7ffffb7dbfefddff5fffffefdbffffffffffedfefffffff7fbe9fdffffdb5feffffffbfdbefff3ffdf7f3fc6ff7fffbffff9df6fbbaf3beffefffffff","sync_committee_signature":"0xa9cf7d9f23a62e84f11851e2e4b3b929b1d03719a780b59ecba5daf57e21a0ceccaf13db4e1392a42e3603abeb839a2d16373dcdd5e696f11c5a809972c1e368d794f1c61d4d10b220df52616032f09b33912febf8c7a64f3ce067ab771c7ddf"},"execution_payload_header":{"parent_hash":"0x71c564f4a0c1dea921e8063fc620ccfa39c1b073e4ac0845ce7e9e6f909752de","fee_recipient":"0x148914866080716b10D686F5570631Fbb2207002","state_root":"0x89e74be562cd4a10eb20cdf674f65b1b0e53b33a7c3f2df848eb4f7e226742e0","receipts_root":"0x55b494ee1bb919e7abffaab1d5be05a109612c59a77406d929d77c0ce714f21d","logs_bloom":"0x20500886140245d001002010680c10411a2540420182810440a108800fc008440801180020011008004045005a2007826802e102000005c0c04030590004044810d0d20745c0904a4d583008a01758018001082024e40046000410020042400100012260220299a8084415e20002891224c132220010003a00006010020ed0c108920a13c0e200a1a00251100888c01408008132414068c88b028920440248209a280581a0e10800c14ea63082c1781308208b130508d4000400802d1224521094260912473404012810001503417b4050141100c1103004000c8900644560080472688450710084088800c4c80000c02008931188204c008009011784488060","prev_randao":"0xf4e9a4a7b88a3d349d779e13118b6d099f7773ec5323921343ac212df19c620f","block_number":"2643688","gas_limit":"30000000","gas_used":"24445884","timestamp":"1730367348","extra_data":"0x546974616e2028746974616e6275696c6465722e78797a29","base_fee_per_gas":"122747440","block_hash":"0x7524d779d328159e4d9ee8a4b04c4b251261da9a6da1d1461243125faa447227","transactions_root":"0x7e8a3391a77eaea563bf4e0ca4cf3190425b591ed8572818924c38f7e423c257","withdrawals_root":"0x61a5653b614ec3db0745ae5568e6de683520d84bc3db2dedf6a5158049cee807","blob_gas_used":"0","excess_blob_gas":"0"},"bls_to_execution_changes":[],"blob_kzg_commitments":[]}},"signature":"0x94320e6aecd65da3ef3e55e45208978844b262fe21cacbb0a8448b2caf21e8619b205c830116d8aad0a2c55d879fb571123a3fcf31b515f9508eb346ecd3de2db07cea6700379c00831cfb439f4aeb3bfa164395367c8d8befb92aa6682eae51"}`)
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v2/beacon/blinded", target), http.MethodPost, body, 404)
}

// sync committee duty requests
func submitSyncCommittee(ctx context.Context, target string) (time.Duration, error) {
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

func submitSyncCommitteeContribution(ctx context.Context, target string) (time.Duration, error) {
	body := strings.NewReader(`[{"message":{"aggregator_index":"1","contribution":{"slot":"1","beacon_block_root":"0xace2cad95a1b113457ccc680372880694a3ef820584d04a165aa2bda0f261950","subcommittee_index":"3","aggregation_bits":"0xfffffbfff7ddffffbef3bfffebffff7f","signature":"0xaa4cf0db0677555025fe12223572e67b509b0b24a2b07dc162aed38522febb2a64ad293e6dbfa1b81481eec250a2cdb61619456291f8d0e3f86097a42a71985d6dabd256107af8b4dfc2982a7d67ac63e2d6b7d59d24a9e87546c71b9c68ca1f"},"selection_proof":"0xb177453ba19233da0625b354d6a43e8621b676243ec4aa5dbb269ac750079cc23fced007ea6cdc1bfb6cc0e2fc796fbb154abed04d9aac7c1171810085beff2b9e5cff961975dbdce4199f39d97b4c46339e26eb7946762394905dbdb9818afe"},"signature":"0x8f73f3185164454f6807549bcbf9d1b0b5516279f35ead1a97812da5db43088de344fdc46aaafd20650bd6685515fb4e18f9f053e9e3691065f8a87f6160456ef8aa550f969ef8260368aae3e450e8763c6317f40b09863ad9b265a0e618e472"}]`)
	return requestRTT(ctx, fmt.Sprintf("%v/eth/v1/validator/contribution_and_proofs", target), http.MethodPost, body, 200)
}
