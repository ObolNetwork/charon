// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/spf13/cobra"
)

type testConfig struct {
	OutputFormat string
	OutputFile   string
	Quiet        bool
	TestCases    []string
	Timeout      time.Duration
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
	cmd.Flags().StringVar(&config.OutputFile, "output-file", "", "File path to which output can be written.")
	cmd.Flags().StringVar(&config.OutputFormat, "output-format", "json", "File format to which output is written. Flag --output-file is required.")
	cmd.Flags().StringSliceVar(&config.TestCases, "test-cases", nil, "List of comma separated names of tests to be exeucted.")
	cmd.Flags().DurationVar(&config.Timeout, "timeout", 24*time.Hour, "Execution timeout for all tests.")
	cmd.Flags().BoolVar(&config.Quiet, "quiet", false, "Do not print test results to stdout.")
}

type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	err := json.Unmarshal(b, &v)
	if err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		d.Duration = time.Duration(value)
		return nil
	case string:
		d.Duration, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("invalid duration")
	}
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
	Error       string      `json:"error"`
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

func writeResultToFile(res testCategoryResult, cfg testConfig) {
	var data []byte
	switch cfg.OutputFormat {
	case "json":
		jsonData, err := json.Marshal(res)
		if err != nil {
			data = []byte(err.Error())
			break
		}
		data = jsonData
	default:
		fmt.Printf("output format %v not supported\n", cfg.OutputFormat)
	}
	os.WriteFile(cfg.OutputFile, data, 0644)
}

func writeResultToWriter(res testCategoryResult, w io.Writer) {
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
		lines[0] = lines[0] + "          "
		lines[1] = lines[1] + "    /\\    "
		lines[2] = lines[2] + "   /  \\   "
		lines[3] = lines[3] + "  / /\\ \\  "
		lines[4] = lines[4] + " / ____ \\ "
		lines[5] = lines[5] + "/_/    \\_\\"
	case categoryScoreB:
		lines[0] = lines[0] + " ____     "
		lines[1] = lines[1] + "|  _ \\    "
		lines[2] = lines[2] + "| |_) |   "
		lines[3] = lines[3] + "|  _ <    "
		lines[4] = lines[4] + "| |_) |   "
		lines[5] = lines[5] + "|____/    "
	case categoryScoreC:
		lines[0] = lines[0] + "   ____     "
		lines[1] = lines[1] + " / ____|   "
		lines[2] = lines[2] + "| |       "
		lines[3] = lines[3] + "| |       "
		lines[4] = lines[4] + "| |____   "
		lines[5] = lines[5] + " \\_____|  "
	}

	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("%-60s%s", "TEST NAME", "RESULT"))
	suggestions := []string{}
	for name, singleTestRes := range res.TestsExecuted {
		testOutput := ""
		testOutput = testOutput + fmt.Sprintf("%-60s", name)
		if singleTestRes.Measurement != "" {
			testOutput = strings.TrimSuffix(testOutput, strings.Repeat(" ", len(singleTestRes.Measurement)+1))
			testOutput = testOutput + singleTestRes.Measurement + " "
		}
		testOutput = testOutput + string(singleTestRes.Verdict)

		if singleTestRes.Suggestion != "" {
			suggestions = append(suggestions, singleTestRes.Suggestion)
		}

		if singleTestRes.Error != "" {
			testOutput = testOutput + " - " + singleTestRes.Error
		}
		lines = append(lines, testOutput)
	}

	if len(suggestions) != 0 {
		lines = append(lines, "")
		lines = append(lines, "IMPROVEMENT SUGGESTIONS")
		lines = append(lines, suggestions...)
	}

	lines = append(lines, "")
	lines = append(lines, res.ExecutionTime.String())

	lines = append(lines, "")
	for _, l := range lines {
		w.Write([]byte(l + "\n"))
	}
}

func calculateScore(results map[string]testResult) categoryScore {
	// TODO(kalo): calculate score more elaborately (potentially use weights)
	belowAvg := 0
	for _, t := range results {
		if t.Verdict == testVerdictNotOk || t.Verdict == testVerdictBad || t.Verdict == testVerdictFail || t.Verdict == testVerdictTimeout {
			return categoryScoreC
		}
		if t.Verdict == testVerdictGood {
			belowAvg += 1
		}
		if t.Verdict == testVerdictAvg {
			belowAvg -= 1
		}
	}

	if belowAvg < 0 {
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
			return nil, fmt.Errorf("test case %v not supported", tc)
		}
	}

	return filteredTests, nil
}
