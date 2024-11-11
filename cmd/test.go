// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/signal"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/exp/maps"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

var (
	errTimeoutInterrupted = testResultError{errors.New("timeout/interrupted")}
	errNoTicker           = testResultError{errors.New("no ticker")}
)

const (
	peersTestCategory       = "peers"
	beaconTestCategory      = "beacon"
	validatorTestCategory   = "validator"
	mevTestCategory         = "mev"
	performanceTestCategory = "performance"
	allTestCategory         = "all"
)

type testConfig struct {
	OutputToml string
	Quiet      bool
	TestCases  []string
	Timeout    time.Duration
}

func newTestCmd(cmds ...*cobra.Command) *cobra.Command {
	root := &cobra.Command{
		Use:   "test",
		Short: "Test subcommands provide test suite to evaluate current cluster setup",
		Long:  `Test subcommands provide test suite to evaluate current cluster setup. The full validator stack can be tested - charon peers, consensus layer, validator client, MEV. Current machine's performance can be examined as well.`,
	}

	root.AddCommand(cmds...)

	return root
}

func bindTestFlags(cmd *cobra.Command, config *testConfig) {
	cmd.Flags().StringVar(&config.OutputToml, "output-toml", "", "File path to which output can be written in TOML format.")
	cmd.Flags().StringSliceVar(&config.TestCases, "test-cases", nil, fmt.Sprintf("List of comma separated names of tests to be exeucted. Available tests are: %v", listTestCases(cmd)))
	cmd.Flags().DurationVar(&config.Timeout, "timeout", time.Hour, "Execution timeout for all tests.")
	cmd.Flags().BoolVar(&config.Quiet, "quiet", false, "Do not print test results to stdout.")
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
		testCaseNames = maps.Keys(supportedPeerTestCases())
		testCaseNames = append(testCaseNames, maps.Keys(supportedSelfTestCases())...)
	case beaconTestCategory:
		testCaseNames = maps.Keys(supportedBeaconTestCases())
	case validatorTestCategory:
		testCaseNames = maps.Keys(supportedValidatorTestCases())
	case mevTestCategory:
		testCaseNames = maps.Keys(supportedMEVTestCases())
	case performanceTestCategory:
		testCaseNames = maps.Keys(supportedPerformanceTestCases())
	case allTestCategory:
		testCaseNames = slices.Concat(
			maps.Keys(supportedPeerTestCases()),
			maps.Keys(supportedSelfTestCases()),
			maps.Keys(supportedRelayTestCases()),
			maps.Keys(supportedBeaconTestCases()),
			maps.Keys(supportedValidatorTestCases()),
			maps.Keys(supportedMEVTestCases()),
			maps.Keys(supportedPerformanceTestCases()),
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
	if cmd.Flag("quiet").Changed && !cmd.Flag("output-toml").Changed {
		return errors.New("on --quiet, an --output-toml is required")
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

// toml fails on marshaling errors to string, so we wrap the errors and add custom marshal
type testResultError struct{ error }

type testResult struct {
	Name         string
	Verdict      testVerdict
	Measurement  string
	Suggestion   string
	Error        testResultError
	IsAcceptable bool
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
	CategoryName  string
	Targets       map[string][]testResult
	ExecutionTime Duration
	Score         categoryScore
}

func appendScore(cat []string, score []string) []string {
	var res []string
	for i, l := range cat {
		res = append(res, l+score[i])
	}

	return res
}

func writeResultToFile(res testCategoryResult, path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o444)
	if err != nil {
		return errors.Wrap(err, "create/open file")
	}
	defer f.Close()
	err = toml.NewEncoder(f).Encode(res)
	if err != nil {
		return errors.Wrap(err, "encode testCategoryResult to TOML")
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
	case performanceTestCategory:
		lines = append(lines, performanceASCII()...)
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
	targets := maps.Keys(res.Targets)
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
	testRes.Measurement = Duration{rtt}.String()

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
