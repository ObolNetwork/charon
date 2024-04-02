// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"fmt"
	"io"
	"os"
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
	testVerdictNotOk testVerdict = "NotOK"
	testVerdictOk    testVerdict = "OK"

	// measurement tests
	testVerdictGood testVerdict = "Good"
	testVerdictAvg  testVerdict = "Avg"
	testVerdictBad  testVerdict = "Bad"

	// errored tests
	testVerdictFail    testVerdict = "Fail"
	testVerdictTimeout testVerdict = "Timeout"
)

type categoryScore string

const (
	categoryScoreA categoryScore = "A"
	categoryScoreB categoryScore = "B"
	categoryScoreC categoryScore = "C"
)

type testResult struct {
	Verdict     testVerdict `json:"verdict"`
	Measurement string      `json:"measurement"`
	Suggestion  string      `json:"suggestion"`
	Error       string      `json:"error,omitempty"`
}

type testCaseName struct {
	name  string
	order uint
}

type testCategoryResult struct {
	CategoryName  string                `json:"category_name"`
	TestsExecuted map[string]testResult `json:"tests_executed"`
	ExecutionTime Duration              `json:"execution_time"`
	Score         categoryScore         `json:"score"`
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
		lines = append(lines, "  ____                                                      ")
		lines = append(lines, " |  __ \\                                                    ")
		lines = append(lines, " | |__) |___   ___  _ __  ___                               ")
		lines = append(lines, " |  ___// _ \\ / _ \\| '__|/ __|                              ")
		lines = append(lines, " | |   |  __/|  __/| |   \\__ \\                              ")
		lines = append(lines, " |_|    \\___| \\___||_|   |___/                              ")
	case "beacon":
		lines = append(lines, "  ____                                                      ")
		lines = append(lines, " |  _ \\                                                     ")
		lines = append(lines, " | |_) |  ___   __ _   ___  ___   _ __                      ")
		lines = append(lines, " |  _ <  / _ \\ / _` | / __|/ _ \\ | '_ \\                     ")
		lines = append(lines, " | |_) ||  __/| (_| || (__| (_) || | | |                    ")
		lines = append(lines, " |____/  \\___| \\__,_| \\___|\\___/ |_| |_|                    ")
	case "validator":
		lines = append(lines, " __      __     _  _      _         _                       ")
		lines = append(lines, " \\ \\    / /    | |(_)    | |       | |                      ")
		lines = append(lines, "  \\ \\  / /__ _ | | _   __| |  __ _ | |_  ___   _ __         ")
		lines = append(lines, "   \\ \\/ // _` || || | / _` | / _` || __|/ _ \\ | '__|        ")
		lines = append(lines, "    \\  /| (_| || || || (_| || (_| || |_| (_) || |           ")
		lines = append(lines, "     \\/  \\__,_||_||_| \\__,_| \\__,_| \\__|\\___/ |_|           ")
	default:
		lines = append(lines, "                                                            ")
		lines = append(lines, "                                                            ")
		lines = append(lines, "                                                            ")
		lines = append(lines, "                                                            ")
		lines = append(lines, "                                                            ")
		lines = append(lines, "                                                            ")
	}

	switch res.Score {
	case categoryScoreA:
		lines[0] += "          "
		lines[1] += "    /\\    "
		lines[2] += "   /  \\   "
		lines[3] += "  / /\\ \\  "
		lines[4] += " / ____ \\ "
		lines[5] += "/_/    \\_\\"
	case categoryScoreB:
		lines[0] += " ____     "
		lines[1] += "|  _ \\    "
		lines[2] += "| |_) |   "
		lines[3] += "|  _ <    "
		lines[4] += "| |_) |   "
		lines[5] += "|____/    "
	case categoryScoreC:
		lines[0] += "   ____     "
		lines[1] += " / ____|   "
		lines[2] += "| |       "
		lines[3] += "| |       "
		lines[4] += "| |____   "
		lines[5] += " \\_____|  "
	}

	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("%-60s%s", "TEST NAME", "RESULT"))
	suggestions := []string{}
	for name, singleTestRes := range res.TestsExecuted {
		testOutput := ""
		testOutput += fmt.Sprintf("%-60s", name)
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

func calculateScore(results map[string]testResult) categoryScore {
	// TODO(kalo): calculate score more elaborately (potentially use weights)
	avg := 0
	for _, t := range results {
		switch t.Verdict {
		case testVerdictNotOk, testVerdictBad, testVerdictFail, testVerdictTimeout:
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

func filterTests(supportedTestCases []testCaseName, cfg testConfig) ([]testCaseName, error) {
	if cfg.TestCases == nil {
		return supportedTestCases, nil
	}
	var filteredTests []testCaseName
	for _, tc := range cfg.TestCases {
		added := false
		for _, stc := range supportedTestCases {
			if stc.name == tc {
				filteredTests = append(filteredTests, stc)
				added = true

				continue
			}
		}
		if !added {
			return nil, errors.New("test case not supported")
		}
	}

	return filteredTests, nil
}
