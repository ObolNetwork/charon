// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"
	"golang.org/x/sys/unix"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

type testPerformanceConfig struct {
	testConfig
	DiskWriteMB int
}

const (
	diskWriteLoops  = 5
	diskWriteMBsAvg = 1000
	diskWriteMBsBad = 500
)

func newTestPerformanceCmd(runFunc func(context.Context, io.Writer, testPerformanceConfig) error) *cobra.Command {
	var config testPerformanceConfig

	cmd := &cobra.Command{
		Use:   "performance",
		Short: "Run multiple hardware and connectivity performance tests",
		Long:  `Run multiple hardware and connectivity performance tests. Verify that Charon is running on sufficient hardware.`,
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return mustOutputToFileOnQuiet(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFunc(cmd.Context(), cmd.OutOrStdout(), config)
		},
	}

	bindTestFlags(cmd, &config.testConfig)
	bindTestPerformanceFlags(cmd, &config)

	return cmd
}

func bindTestPerformanceFlags(cmd *cobra.Command, config *testPerformanceConfig) {
	cmd.Flags().IntVar(&config.DiskWriteMB, "disk-write-mb", 4096, "Size of file to be created that is used for write speed test")
}

func supportedPerformanceTestCases() map[testCaseName]func(context.Context, *testPerformanceConfig) testResult {
	return map[testCaseName]func(context.Context, *testPerformanceConfig) testResult{
		{name: "diskWrite", order: 1}: performanceDiskWriteTest,
	}
}

func runTestPerformance(ctx context.Context, w io.Writer, cfg testPerformanceConfig) (err error) {
	testCases := supportedPerformanceTestCases()
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

	go testSinglePerformance(timeoutCtx, queuedTests, testCases, cfg, testResultsChan)

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
		CategoryName:  performanceTestCategory,
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

func testSinglePerformance(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]func(context.Context, *testPerformanceConfig) testResult, cfg testPerformanceConfig, resCh chan map[string][]testResult) {
	defer close(resCh)
	singleTestResCh := make(chan testResult)
	allTestRes := []testResult{}
	// run all performance tests for a performance client, pushing each completed test to the channel until all are complete or timeout occurs
	go testPerformance(ctx, queuedTestCases, allTestCases, cfg, singleTestResCh)

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

	resCh <- map[string][]testResult{"local": allTestRes}
}

func testPerformance(ctx context.Context, queuedTests []testCaseName, allTests map[testCaseName]func(context.Context, *testPerformanceConfig) testResult, cfg testPerformanceConfig, ch chan testResult) {
	defer close(ch)
	for _, t := range queuedTests {
		select {
		case <-ctx.Done():
			return
		default:
			ch <- allTests[t](ctx, &cfg)
		}
	}
}

func performanceDiskWriteTest(ctx context.Context, conf *testPerformanceConfig) testResult {
	testRes := testResult{Name: "DiskWrite"}

	log.Info(ctx, "Testing disk write...",
		z.Any("file size MB", conf.DiskWriteMB),
		z.Any("loops", diskWriteLoops))

	if conf.DiskWriteMB <= 3072 {
		log.Warn(ctx, "File size used for tests of 3072MB or lower impacts the measured performance", nil)
	}

	var stat unix.Statfs_t
	wd, _ := os.Getwd()
	err := unix.Statfs(wd, &stat)
	if err != nil {
		return failedTestResult(testRes, err)
	}
	// Available blocks * size per block = available space in bytes
	availableMB := int(stat.Bavail * uint64(stat.Bsize) / 1024 / 1024)
	actualDiskWriteMB := conf.DiskWriteMB

	for availableMB < actualDiskWriteMB {
		log.Warn(ctx, fmt.Sprintf("Insufficient available disk space of %vMB, reducing the test size to %vMB. Note that this might result in slower write speed", availableMB, actualDiskWriteMB), nil)
		actualDiskWriteMB /= actualDiskWriteMB
		if actualDiskWriteMB == 0 {
			return failedTestResult(testRes, errors.New("insufficient available disk space", z.Str("available_space", strconv.Itoa(availableMB)+"MB")))
		}
	}

	var diskWriteTotal float64
	for range diskWriteLoops {
		time, err := writeFile(float64(actualDiskWriteMB) / 1024)
		if err != nil {
			return failedTestResult(testRes, err)
		}
		diskWriteTotal += time
	}

	diskWriteFinal := diskWriteTotal / diskWriteLoops

	if diskWriteFinal < diskWriteMBsBad {
		testRes.Verdict = testVerdictBad
	} else if diskWriteFinal < diskWriteMBsAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = strconv.FormatFloat(diskWriteFinal, 'f', 4, 64) + "MB/s"

	return testRes
}

func writeFile(fSize float64) (float64, error) {
	fSize *= 1024 * 1024 * 1024 // size in GB
	ex, err := os.Executable()
	if err != nil {
		return 0, errors.Wrap(err, "os executable write file")
	}
	exPath := filepath.Dir(ex)
	fName := exPath + `/diskio`
	defer os.Remove(fName)
	f, err := os.Create(fName)
	if err != nil {
		return 0, errors.Wrap(err, "os create write file")
	}
	const defaultBufSize = 4096
	buf := make([]byte, defaultBufSize)
	buf[len(buf)-1] = '\n'
	w := bufio.NewWriterSize(f, len(buf))

	start := time.Now()
	written := int64(0)
	for i := int64(0); i < int64(fSize); i += int64(len(buf)) {
		nn, err := w.Write(buf)
		if err != nil {
			return 0, errors.Wrap(err, "write to file")
		}
		written += int64(nn)
	}
	err = w.Flush()
	if err != nil {
		return 0, errors.Wrap(err, "flush file")
	}
	err = f.Sync()
	if err != nil {
		return 0, errors.Wrap(err, "sync file")
	}
	since := time.Since(start)

	err = f.Close()
	if err != nil {
		return 0, errors.Wrap(err, "close file")
	}

	actulMBWritten := float64(written) / 1024 / 1024

	return actulMBWritten / since.Seconds(), nil
}
