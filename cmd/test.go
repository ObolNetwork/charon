// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	ssz "github.com/ferranbt/fastssz"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/enr"
)

var (
	errTimeoutInterrupted = testResultError{errors.New("timeout/interrupted")}
	errNoTicker           = testResultError{errors.New("no ticker")}
)

const (
	peersTestCategory     = "peers"
	beaconTestCategory    = "beacon"
	validatorTestCategory = "validator"
	mevTestCategory       = "mev"
	infraTestCategory     = "infra"
	allTestCategory       = "all"

	committeeSizePerSlot = 64
	subCommitteeSize     = 4
	slotTime             = 12 * time.Second
	slotsInEpoch         = 32
	epochTime            = slotsInEpoch * slotTime
)

type testConfig struct {
	OutputJSON            string
	Quiet                 bool
	TestCases             []string
	Timeout               time.Duration
	Publish               bool
	PublishAddr           string
	PublishPrivateKeyFile string
}

func newTestCmd(cmds ...*cobra.Command) *cobra.Command {
	root := &cobra.Command{
		Use:   "test",
		Short: "Test subcommands provide test suite to evaluate current cluster setup",
		Long:  `Test subcommands provide test suite to evaluate current cluster setup. The full validator stack can be tested - charon peers, consensus layer, validator client, MEV. Current machine's infra can be examined as well.`,
	}

	root.AddCommand(cmds...)

	return root
}

func bindTestFlags(cmd *cobra.Command, config *testConfig) {
	cmd.Flags().StringVar(&config.OutputJSON, "output-json", "", "File path to which output can be written in JSON format.")
	cmd.Flags().StringSliceVar(&config.TestCases, "test-cases", nil, fmt.Sprintf("List of comma separated names of tests to be exeucted. Available tests are: %v", listTestCases(cmd)))
	cmd.Flags().DurationVar(&config.Timeout, "timeout", time.Hour, "Execution timeout for all tests.")
	cmd.Flags().BoolVar(&config.Quiet, "quiet", false, "Do not print test results to stdout.")
	cmd.Flags().BoolVar(&config.Publish, "publish", false, "Publish test result file to obol-api.")
	cmd.Flags().StringVar(&config.PublishAddr, "publish-address", "https://api.obol.tech/v1", "The URL to publish the test result file to.")
	cmd.Flags().StringVar(&config.PublishPrivateKeyFile, "publish-private-key-file", ".charon/charon-enr-private-key", "The path to the charon enr private key file, used for signing the publish request. Temporary key will be generated if the file does not exist.")
}

func bindTestLogFlags(flags *pflag.FlagSet, config *log.Config) {
	flags.StringVar(&config.Format, "log-format", "console", "Log format; console, logfmt or json")
	flags.StringVar(&config.Level, "log-level", "info", "Log level; debug, info, warn or error")
	flags.StringVar(&config.Color, "log-color", "auto", "Log color; auto, force, disable.")
	flags.StringVar(&config.LogOutputPath, "log-output-path", "", "Path in which to write on-disk logs.")
}

func listTestCases(cmd *cobra.Command) []string {
	var testCaseNames []testCaseName
	switch cmd.Name() {
	case peersTestCategory:
		testCaseNames = slices.Collect(maps.Keys(supportedPeerTestCases()))
		testCaseNames = append(testCaseNames, slices.Collect(maps.Keys(supportedSelfTestCases()))...)
	case beaconTestCategory:
		testCaseNames = slices.Collect(maps.Keys(supportedBeaconTestCases()))
	case validatorTestCategory:
		testCaseNames = slices.Collect(maps.Keys(supportedValidatorTestCases()))
	case mevTestCategory:
		testCaseNames = slices.Collect(maps.Keys(supportedMEVTestCases()))
	case infraTestCategory:
		testCaseNames = slices.Collect(maps.Keys(supportedInfraTestCases()))
	case allTestCategory:
		testCaseNames = slices.Concat(
			slices.Collect(maps.Keys(supportedPeerTestCases())),
			slices.Collect(maps.Keys(supportedSelfTestCases())),
			slices.Collect(maps.Keys(supportedRelayTestCases())),
			slices.Collect(maps.Keys(supportedBeaconTestCases())),
			slices.Collect(maps.Keys(supportedValidatorTestCases())),
			slices.Collect(maps.Keys(supportedMEVTestCases())),
			slices.Collect(maps.Keys(supportedInfraTestCases())),
		)
	default:
		log.Warn(cmd.Context(), "Unknown command for listing test cases", nil, z.Str("name", cmd.Name()))
	}

	var stringNames []string
	for _, tcn := range testCaseNames {
		stringNames = append(stringNames, tcn.name)
	}

	return stringNames
}

func mustOutputToFileOnQuiet(cmd *cobra.Command) error {
	if cmd.Flag("quiet").Changed && !cmd.Flag("output-json").Changed {
		return errors.New("on --quiet, an --output-json is required")
	}

	return nil
}

type testVerdict string

const (
	// boolean tests
	testVerdictOk testVerdict = "OK"

	// measurement tests
	testVerdictGood testVerdict = "Good"
	testVerdictAvg  testVerdict = "Avg"
	testVerdictPoor testVerdict = "Poor"

	// failed tests
	testVerdictFail testVerdict = "Fail"

	// skipped tests
	testVerdictSkipped testVerdict = "Skip"
)

type categoryScore string

const (
	categoryScoreA categoryScore = "A"
	categoryScoreB categoryScore = "B"
	categoryScoreC categoryScore = "C"
)

type testResultError struct{ error }

type testResult struct {
	Name         string          `json:"name"`
	Verdict      testVerdict     `json:"verdict"`
	Measurement  string          `json:"measurement,omitempty"`
	Suggestion   string          `json:"suggestion,omitempty"`
	Error        testResultError `json:"error,omitempty"`
	IsAcceptable bool            `json:"-"`
}

func failedTestResult(testRes testResult, err error) testResult {
	testRes.Verdict = testVerdictFail
	testRes.Error = testResultError{err}

	return testRes
}

func httpStatusError(code int) string {
	return fmt.Sprintf("HTTP status code %v", code)
}

func (s *testResultError) UnmarshalText(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	s.error = errors.New(string(data))

	return nil
}

// MarshalText implements encoding.TextMarshaler
func (s testResultError) MarshalText() ([]byte, error) {
	if s.error == nil {
		return []byte{}, nil
	}

	return []byte(s.Error()), nil
}

type testCaseName struct {
	name  string
	order uint
}

type testCategoryResult struct {
	CategoryName  string                  `json:"category_name,omitempty"`
	Targets       map[string][]testResult `json:"targets,omitempty"`
	ExecutionTime Duration                `json:"execution_time,omitempty"`
	Score         categoryScore           `json:"score,omitempty"`
}

type allCategoriesResult struct {
	Peers     testCategoryResult `json:"charon_peers,omitempty"`
	Beacon    testCategoryResult `json:"beacon_node,omitempty"`
	Validator testCategoryResult `json:"validator_client,omitempty"`
	MEV       testCategoryResult `json:"mev,omitempty"`
	Infra     testCategoryResult `json:"infra,omitempty"`
}

func appendScore(cat []string, score []string) []string {
	var res []string
	for i, l := range cat {
		res = append(res, l+score[i])
	}

	return res
}

type obolAPIResult struct {
	ENR  string              `json:"enr,omitempty"`
	Sig  []byte              `json:"sig,omitempty"`
	Data allCategoriesResult `json:"data"`
}

func publishResultToObolAPI(ctx context.Context, data allCategoriesResult, path string, privateKeyFile string) error {
	var (
		err        error
		p2pPrivKey *k1.PrivateKey
	)

	if !fileExists(privateKeyFile) {
		p2pPrivKey, err = k1.GeneratePrivateKey()
		if err != nil {
			return errors.Wrap(err, "generate p2p private key")
		}
	} else {
		p2pPrivKey, err = k1util.Load(privateKeyFile)
		if err != nil {
			return errors.Wrap(err, "load p2p private key", z.Str("privateKeyFile", privateKeyFile))
		}
	}

	enr, err := enr.New(p2pPrivKey)
	if err != nil {
		return err
	}

	signDataBytes, err := json.Marshal(data)
	if err != nil {
		return errors.Wrap(err, "marshal all test categories signing data")
	}

	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)

	indx := hh.Index()
	hh.PutBytes(signDataBytes)
	hh.Merkleize(indx)

	hash, err := hh.HashRoot()
	if err != nil {
		return errors.Wrap(err, "hash root")
	}

	sig, err := k1util.Sign(p2pPrivKey, hash[:])
	if err != nil {
		return errors.Wrap(err, "k1 sign")
	}

	obolAPI, err := obolapi.New(path)
	if err != nil {
		return err
	}

	res := obolAPIResult{
		ENR:  enr.String(),
		Sig:  sig,
		Data: data,
	}

	obolAPIJSON, err := json.Marshal(res)
	if err != nil {
		return errors.Wrap(err, "marshal Obol API test struct")
	}

	err = obolAPI.PostTestResult(ctx, obolAPIJSON)
	if err != nil {
		return err
	}

	return nil
}

func writeResultToFile(res testCategoryResult, path string) error {
	// open or create a file
	existingFile, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return errors.Wrap(err, "create/open file")
	}
	defer existingFile.Close()
	stat, err := existingFile.Stat()
	if err != nil {
		return errors.Wrap(err, "get file stat")
	}
	// read file contents or default to empty structure
	var file allCategoriesResult
	if stat.Size() == 0 {
		file = allCategoriesResult{}
	} else {
		err = json.NewDecoder(existingFile).Decode(&file)
		if err != nil {
			return errors.Wrap(err, "decode fileResult from JSON")
		}
	}

	switch res.CategoryName {
	case peersTestCategory:
		file.Peers = res
	case beaconTestCategory:
		file.Beacon = res
	case validatorTestCategory:
		file.Validator = res
	case mevTestCategory:
		file.MEV = res
	case infraTestCategory:
		file.Infra = res
	}

	// write data to temp file
	tmpFile, err := os.CreateTemp(filepath.Dir(path), fmt.Sprintf("%v-tmp-*.json", filepath.Base(path)))
	if err != nil {
		return errors.Wrap(err, "create temp file")
	}
	defer tmpFile.Close()
	err = tmpFile.Chmod(0o644)
	if err != nil {
		return errors.Wrap(err, "chmod temp file")
	}

	fileContentJSON, err := json.Marshal(file)
	if err != nil {
		return errors.Wrap(err, "marshal fileResult to JSON")
	}

	_, err = tmpFile.Write(fileContentJSON)
	if err != nil {
		return errors.Wrap(err, "write json to file")
	}

	err = os.Rename(tmpFile.Name(), path)
	if err != nil {
		return errors.Wrap(err, "rename temp file")
	}

	return nil
}

func writeResultToWriter(res testCategoryResult, w io.Writer) error {
	var lines []string

	switch res.CategoryName {
	case peersTestCategory:
		lines = append(lines, peersASCII()...)
	case beaconTestCategory:
		lines = append(lines, beaconASCII()...)
	case validatorTestCategory:
		lines = append(lines, validatorASCII()...)
	case mevTestCategory:
		lines = append(lines, mevASCII()...)
	case infraTestCategory:
		lines = append(lines, infraASCII()...)
	default:
		lines = append(lines, categoryDefaultASCII()...)
	}

	switch res.Score {
	case categoryScoreA:
		lines = appendScore(lines, scoreAASCII())
	case categoryScoreB:
		lines = appendScore(lines, scoreBASCII())
	case categoryScoreC:
		lines = appendScore(lines, scoreCASCII())
	}

	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("%-64s%s", "TEST NAME", "RESULT"))
	suggestions := []string{}
	targets := slices.Collect(maps.Keys(res.Targets))
	slices.Sort(targets)
	for _, target := range targets {
		if target != "" && len(res.Targets[target]) > 0 {
			lines = append(lines, "")
			lines = append(lines, target)
		}
		for _, singleTestRes := range res.Targets[target] {
			testOutput := ""
			testOutput += fmt.Sprintf("%-64s", singleTestRes.Name)
			if singleTestRes.Measurement != "" {
				testOutput = strings.TrimSuffix(testOutput, strings.Repeat(" ", utf8.RuneCountInString(singleTestRes.Measurement)+1))
				testOutput = testOutput + singleTestRes.Measurement + " "
			}
			testOutput += string(singleTestRes.Verdict)

			if singleTestRes.Suggestion != "" {
				suggestions = append(suggestions, singleTestRes.Suggestion)
			}

			if singleTestRes.Error.error != nil {
				testOutput += " - " + singleTestRes.Error.Error()
			}
			lines = append(lines, testOutput)
		}
	}
	if len(suggestions) != 0 {
		lines = append(lines, "")
		lines = append(lines, "SUGGESTED IMPROVEMENTS")
		lines = append(lines, suggestions...)
	}

	lines = append(lines, "")
	lines = append(lines, res.ExecutionTime.String())

	lines = append(lines, "")
	for _, l := range lines {
		_, err := w.Write([]byte(l + "\n"))
		if err != nil {
			return err
		}
	}

	return nil
}

func evaluateHighestRTTScores(testResCh chan time.Duration, testRes testResult, avg time.Duration, poor time.Duration) testResult {
	highestRTT := time.Duration(0)
	for rtt := range testResCh {
		if rtt > highestRTT {
			highestRTT = rtt
		}
	}

	return evaluateRTT(highestRTT, testRes, avg, poor)
}

func evaluateRTT(rtt time.Duration, testRes testResult, avg time.Duration, poor time.Duration) testResult {
	if rtt == 0 || rtt > poor {
		testRes.Verdict = testVerdictPoor
	} else if rtt > avg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = RoundDuration(Duration{rtt}).String()

	return testRes
}

func calculateScore(results []testResult) categoryScore {
	// TODO(kalo): calculate score more elaborately (potentially use weights)
	avg := 0
	for _, t := range results {
		switch t.Verdict {
		case testVerdictPoor:
			return categoryScoreC
		case testVerdictGood:
			avg++
		case testVerdictAvg:
			avg--
		case testVerdictFail:
			if !t.IsAcceptable {
				return categoryScoreC
			}

			continue
		case testVerdictOk, testVerdictSkipped:
			continue
		}
	}

	if avg < 0 {
		return categoryScoreB
	}

	return categoryScoreA
}

func filterTests(supportedTestCases []testCaseName, cfg testConfig) []testCaseName {
	if cfg.TestCases == nil {
		return supportedTestCases
	}
	var filteredTests []testCaseName
	for _, tc := range cfg.TestCases {
		for _, stc := range supportedTestCases {
			if stc.name == tc {
				filteredTests = append(filteredTests, stc)
				continue
			}
		}
	}

	return filteredTests
}

func sortTests(tests []testCaseName) {
	sort.Slice(tests, func(i, j int) bool {
		return tests[i].order < tests[j].order
	})
}

func blockAndWait(ctx context.Context, awaitTime time.Duration) {
	notifyCtx, cancelNotifyCtx := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancelNotifyCtx()
	keepAliveCtx, cancelKeepAliveCtx := context.WithTimeout(ctx, awaitTime)
	defer cancelKeepAliveCtx()
	select {
	case <-keepAliveCtx.Done():
		log.Info(ctx, "Await time reached or interrupted")
	case <-notifyCtx.Done():
		log.Info(ctx, "Forcefully stopped")
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

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !os.IsNotExist(err)
}
