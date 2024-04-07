// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
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
		Long:  `Test subcommands provide test suite to evaluate current cluster setup. Currently there is support for peer connection tests, beacon node and validator API.`,
	}

	root.AddCommand(cmds...)

	return root
}

func bindTestFlags(cmd *cobra.Command, config *testConfig) {
	cmd.Flags().StringVar(&config.OutputToml, "output-toml", "", "File path to which output can be written in TOML format.")
	cmd.Flags().StringSliceVar(&config.TestCases, "test-cases", nil, "List of comma separated names of tests to be exeucted.")
	cmd.Flags().DurationVar(&config.Timeout, "timeout", 24*time.Hour, "Execution timeout for all tests.")
	cmd.Flags().BoolVar(&config.Quiet, "quiet", false, "Do not print test results to stdout.")
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
	testVerdictBad  testVerdict = "Bad"

	// failed tests
	testVerdictFail testVerdict = "Fail"
)

type categoryScore string

const (
	categoryScoreA categoryScore = "A"
	categoryScoreB categoryScore = "B"
	categoryScoreC categoryScore = "C"
)

type testResult struct {
	Name        string
	Verdict     testVerdict
	Measurement string
	Suggestion  string
	Error       string
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
	case "peers":
		lines = append(lines, peersASCII()...)
	case "beacon":
		lines = append(lines, beaconASCII()...)
	case "validator":
		lines = append(lines, validatorASCII()...)
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
	lines = append(lines, fmt.Sprintf("%-60s%s", "TEST NAME", "RESULT"))
	suggestions := []string{}
	for target, testResults := range res.Targets {
		if target != "" && len(testResults) > 0 {
			lines = append(lines, "")
			lines = append(lines, target)
		}
		for _, singleTestRes := range testResults {
			testOutput := ""
			testOutput += fmt.Sprintf("%-60s", singleTestRes.Name)
			if singleTestRes.Measurement != "" {
				testOutput = strings.TrimSuffix(testOutput, strings.Repeat(" ", len(singleTestRes.Measurement)+1))
				testOutput = testOutput + singleTestRes.Measurement + " "
			}
			testOutput += string(singleTestRes.Verdict)

			if singleTestRes.Suggestion != "" {
				suggestions = append(suggestions, singleTestRes.Suggestion)
			}

			if singleTestRes.Error != "" {
				testOutput += " - " + singleTestRes.Error
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

func calculateScore(results []testResult) categoryScore {
	// TODO(kalo): calculate score more elaborately (potentially use weights)
	avg := 0
	for _, t := range results {
		switch t.Verdict {
		case testVerdictBad, testVerdictFail:
			return categoryScoreC
		case testVerdictGood:
			avg++
		case testVerdictAvg:
			avg--
		case testVerdictOk:
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
