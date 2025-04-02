// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/showwin/speedtest-go/speedtest"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

type testInfraConfig struct {
	testConfig
	DiskIOTestFileDir          string
	DiskIOBlockSizeKb          int
	InternetTestServersOnly    []string
	InternetTestServersExclude []string
	DiskTestTool               DiskTestTool
}

type fioResult struct {
	Jobs []fioResultJobs `json:"jobs"`
}

type fioResultJobs struct {
	Read  fioResultSingle `json:"read"`
	Write fioResultSingle `json:"write"`
}

type fioResultSingle struct {
	Iops float64 `json:"iops"`
	Bw   float64 `json:"bw"`
}

const (
	diskOpsNumOfJobs      = 8
	diskOpsMBsTotal       = 4096 // split between number of jobs
	diskWriteSpeedMBsAvg  = 1000
	diskWriteSpeedMBsPoor = 500
	diskWriteIOPSAvg      = 2000
	diskWriteIOPSPoor     = 1000
	diskReadSpeedMBsAvg   = 1000
	diskReadSpeedMBsPoor  = 500
	diskReadIOPSAvg       = 2000
	diskReadIOPSPoor      = 1000

	availableMemoryMBsAvg  = 4000
	availableMemoryMBsPoor = 2000
	totalMemoryMBsAvg      = 8000
	totalMemoryMBsPoor     = 4000

	internetLatencyAvg            = 20 * time.Millisecond
	internetLatencyPoor           = 50 * time.Millisecond
	internetDownloadSpeedMbpsAvg  = 50
	internetDownloadSpeedMbpsPoor = 15
	internetUploadSpeedMbpsAvg    = 50
	internetUploadSpeedMbpsPoor   = 15
)

var errFioNotFound = errors.New("fio command not found, install fio from https://fio.readthedocs.io/en/latest/fio_doc.html#binary-packages or using the package manager of your choice (apt, yum, brew, etc.)")

func newTestInfraCmd(runFunc func(context.Context, io.Writer, testInfraConfig) (res testCategoryResult, err error)) *cobra.Command {
	var config testInfraConfig

	cmd := &cobra.Command{
		Use:   "infra",
		Short: "Run multiple hardware and internet connectivity tests",
		Long:  `Run multiple hardware and internet connectivity tests. Verify that Charon is running on host with sufficient capabilities.`,
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return mustOutputToFileOnQuiet(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := runFunc(cmd.Context(), cmd.OutOrStdout(), config)
			return err
		},
	}

	bindTestFlags(cmd, &config.testConfig)
	bindTestInfraFlags(cmd, &config, "")
	config.DiskTestTool = FioTestTool{}

	return cmd
}

func bindTestInfraFlags(cmd *cobra.Command, config *testInfraConfig, flagsPrefix string) {
	cmd.Flags().StringVar(&config.DiskIOTestFileDir, flagsPrefix+"disk-io-test-file-dir", "", "Directory at which disk performance will be measured. If none specified, current user's home directory will be used.")
	cmd.Flags().IntVar(&config.DiskIOBlockSizeKb, flagsPrefix+"disk-io-block-size-kb", 4096, "The block size in kilobytes used for I/O units. Same value applies for both reads and writes.")
	cmd.Flags().StringSliceVar(&config.InternetTestServersOnly, flagsPrefix+"internet-test-servers-only", []string{}, "List of specific server names to be included for the internet tests, the best performing one is chosen. If not provided, closest and best performing servers are chosen automatically.")
	cmd.Flags().StringSliceVar(&config.InternetTestServersExclude, flagsPrefix+"internet-test-servers-exclude", []string{}, "List of server names to be excluded from the tests. To be specified only if you experience issues with a server that is wrongly considered best performing.")
}

func supportedInfraTestCases() map[testCaseName]func(context.Context, *testInfraConfig) testResult {
	return map[testCaseName]func(context.Context, *testInfraConfig) testResult{
		{name: "DiskWriteSpeed", order: 1}:        infraDiskWriteSpeedTest,
		{name: "DiskWriteIOPS", order: 2}:         infraDiskWriteIOPSTest,
		{name: "DiskReadSpeed", order: 3}:         infraDiskReadSpeedTest,
		{name: "DiskReadIOPS", order: 4}:          infraDiskReadIOPSTest,
		{name: "AvailableMemory", order: 5}:       infraAvailableMemoryTest,
		{name: "TotalMemory", order: 6}:           infraTotalMemoryTest,
		{name: "InternetLatency", order: 7}:       infraInternetLatencyTest,
		{name: "InternetDownloadSpeed", order: 8}: infraInternetDownloadSpeedTest,
		{name: "InternetUploadSpeed", order: 9}:   infraInternetUploadSpeedTest,
	}
}

func runTestInfra(ctx context.Context, w io.Writer, cfg testInfraConfig) (res testCategoryResult, err error) {
	log.Info(ctx, "Starting hardware performance and network connectivity test")

	testCases := supportedInfraTestCases()
	queuedTests := filterTests(slices.Collect(maps.Keys(testCases)), cfg.testConfig)
	if len(queuedTests) == 0 {
		return res, errors.New("test case not supported")
	}
	sortTests(queuedTests)

	timeoutCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	testResultsChan := make(chan map[string][]testResult)
	testResults := make(map[string][]testResult)
	startTime := time.Now()

	go testSingleInfra(timeoutCtx, queuedTests, testCases, cfg, testResultsChan)

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

	res = testCategoryResult{
		CategoryName:  infraTestCategory,
		Targets:       testResults,
		ExecutionTime: execTime,
		Score:         score,
	}

	if !cfg.Quiet {
		err = writeResultToWriter(res, w)
		if err != nil {
			return res, err
		}
	}

	if cfg.OutputJSON != "" {
		err = writeResultToFile(res, cfg.OutputJSON)
		if err != nil {
			return res, err
		}
	}

	return res, nil
}

// hardware and internet connectivity tests

func testSingleInfra(ctx context.Context, queuedTestCases []testCaseName, allTestCases map[testCaseName]func(context.Context, *testInfraConfig) testResult, cfg testInfraConfig, resCh chan map[string][]testResult) {
	defer close(resCh)
	singleTestResCh := make(chan testResult)
	allTestRes := []testResult{}
	// run all infra tests for a client, pushing each completed test to the channel until all are complete or timeout occurs
	go testInfra(ctx, queuedTestCases, allTestCases, cfg, singleTestResCh)

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
			testCounter++
			allTestRes = append(allTestRes, result)
		}
	}

	resCh <- map[string][]testResult{"local": allTestRes}
}

func testInfra(ctx context.Context, queuedTests []testCaseName, allTests map[testCaseName]func(context.Context, *testInfraConfig) testResult, cfg testInfraConfig, ch chan testResult) {
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

func infraDiskWriteSpeedTest(ctx context.Context, conf *testInfraConfig) testResult {
	testRes := testResult{Name: "DiskWriteSpeed"}

	var err error
	var testFilePath string
	if conf.DiskIOTestFileDir == "" {
		testFilePath, err = os.UserHomeDir()
		if err != nil {
			return failedTestResult(testRes, err)
		}
	} else {
		testFilePath = conf.DiskIOTestFileDir
	}

	log.Info(ctx, "Testing disk write speed...",
		z.Any("test_file_size_mb", diskOpsMBsTotal),
		z.Any("jobs", diskOpsNumOfJobs),
		z.Any("test_file_path", testFilePath))

	err = conf.DiskTestTool.CheckAvailability()
	if err != nil {
		return failedTestResult(testRes, err)
	}

	diskWriteMBs, err := conf.DiskTestTool.WriteSpeed(ctx, testFilePath, conf.DiskIOBlockSizeKb)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	if diskWriteMBs < diskWriteSpeedMBsPoor {
		testRes.Verdict = testVerdictPoor
	} else if diskWriteMBs < diskWriteSpeedMBsAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = strconv.FormatFloat(diskWriteMBs, 'f', 2, 64) + "MB/s"

	return testRes
}

func infraDiskWriteIOPSTest(ctx context.Context, conf *testInfraConfig) testResult {
	testRes := testResult{Name: "DiskWriteIOPS"}

	var err error
	var testFilePath string
	if conf.DiskIOTestFileDir == "" {
		testFilePath, err = os.UserHomeDir()
		if err != nil {
			return failedTestResult(testRes, err)
		}
	} else {
		testFilePath = conf.DiskIOTestFileDir
	}

	log.Info(ctx, "Testing disk write IOPS...",
		z.Any("test_file_size_mb", diskOpsMBsTotal),
		z.Any("jobs", diskOpsNumOfJobs),
		z.Any("test_file_path", testFilePath))

	err = conf.DiskTestTool.CheckAvailability()
	if err != nil {
		return failedTestResult(testRes, err)
	}

	diskWriteIOPS, err := conf.DiskTestTool.WriteIOPS(ctx, testFilePath, conf.DiskIOBlockSizeKb)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	if diskWriteIOPS < diskWriteIOPSPoor {
		testRes.Verdict = testVerdictPoor
	} else if diskWriteIOPS < diskWriteIOPSAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = strconv.FormatFloat(diskWriteIOPS, 'f', 0, 64)

	return testRes
}

func infraDiskReadSpeedTest(ctx context.Context, conf *testInfraConfig) testResult {
	testRes := testResult{Name: "DiskReadSpeed"}

	var err error
	var testFilePath string
	if conf.DiskIOTestFileDir == "" {
		testFilePath, err = os.UserHomeDir()
		if err != nil {
			return failedTestResult(testRes, err)
		}
	} else {
		testFilePath = conf.DiskIOTestFileDir
	}

	log.Info(ctx, "Testing disk read speed...",
		z.Any("test_file_size_mb", diskOpsMBsTotal),
		z.Any("jobs", diskOpsNumOfJobs),
		z.Any("test_file_path", testFilePath))

	err = conf.DiskTestTool.CheckAvailability()
	if err != nil {
		return failedTestResult(testRes, err)
	}

	diskReadMBs, err := conf.DiskTestTool.ReadSpeed(ctx, testFilePath, conf.DiskIOBlockSizeKb)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	if diskReadMBs < diskReadSpeedMBsPoor {
		testRes.Verdict = testVerdictPoor
	} else if diskReadMBs < diskReadSpeedMBsAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = strconv.FormatFloat(diskReadMBs, 'f', 2, 64) + "MB/s"

	return testRes
}

func infraDiskReadIOPSTest(ctx context.Context, conf *testInfraConfig) testResult {
	testRes := testResult{Name: "DiskReadIOPS"}

	var err error
	var testFilePath string
	if conf.DiskIOTestFileDir == "" {
		testFilePath, err = os.UserHomeDir()
		if err != nil {
			return failedTestResult(testRes, err)
		}
	} else {
		testFilePath = conf.DiskIOTestFileDir
	}

	log.Info(ctx, "Testing disk read IOPS...",
		z.Any("test_file_size_mb", diskOpsMBsTotal),
		z.Any("jobs", diskOpsNumOfJobs),
		z.Any("test_file_path", testFilePath))

	err = conf.DiskTestTool.CheckAvailability()
	if err != nil {
		return failedTestResult(testRes, err)
	}

	diskReadIOPS, err := conf.DiskTestTool.ReadSpeed(ctx, testFilePath, conf.DiskIOBlockSizeKb)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	if diskReadIOPS < diskReadIOPSPoor {
		testRes.Verdict = testVerdictPoor
	} else if diskReadIOPS < diskReadIOPSAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = strconv.FormatFloat(diskReadIOPS, 'f', 0, 64)

	return testRes
}

func infraAvailableMemoryTest(ctx context.Context, _ *testInfraConfig) testResult {
	testRes := testResult{Name: "AvailableMemory"}

	var availableMemory int64
	var err error
	os := runtime.GOOS
	switch os {
	case "linux":
		availableMemory, err = availableMemoryLinux(ctx)
		if err != nil {
			return failedTestResult(testRes, err)
		}
	case "darwin":
		availableMemory, err = availableMemoryMacos(ctx)
		if err != nil {
			return failedTestResult(testRes, err)
		}
	default:
		return failedTestResult(testRes, errors.New("unknown OS "+os))
	}

	availableMemoryMB := availableMemory / 1024 / 1024

	if availableMemoryMB < availableMemoryMBsPoor {
		testRes.Verdict = testVerdictPoor
	} else if availableMemoryMB < availableMemoryMBsAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = strconv.Itoa(int(availableMemoryMB)) + "MB"

	return testRes
}

func infraTotalMemoryTest(ctx context.Context, _ *testInfraConfig) testResult {
	testRes := testResult{Name: "TotalMemory"}

	var totalMemory int64
	var err error
	os := runtime.GOOS
	switch os {
	case "linux":
		totalMemory, err = totalMemoryLinux(ctx)
		if err != nil {
			return failedTestResult(testRes, err)
		}
	case "darwin":
		totalMemory, err = totalMemoryMacos(ctx)
		if err != nil {
			return failedTestResult(testRes, err)
		}
	default:
		return failedTestResult(testRes, errors.New("unknown OS "+os))
	}

	totalMemoryMB := totalMemory / 1024 / 1024

	if totalMemoryMB < totalMemoryMBsPoor {
		testRes.Verdict = testVerdictPoor
	} else if totalMemoryMB < totalMemoryMBsAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = strconv.Itoa(int(totalMemoryMB)) + "MB"

	return testRes
}

func infraInternetLatencyTest(ctx context.Context, conf *testInfraConfig) testResult {
	testRes := testResult{Name: "InternetLatency"}

	server, err := fetchOoklaServer(ctx, conf)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	log.Info(ctx, "Testing internet latency...",
		z.Any("server_name", server.Name),
		z.Any("server_country", server.Country),
		z.Any("server_distance_km", server.Distance),
		z.Any("server_id", server.ID),
	)
	err = server.PingTestContext(ctx, nil)
	if err != nil {
		return failedTestResult(testRes, err)
	}
	testRes = evaluateRTT(server.Latency, testRes, internetLatencyAvg, internetLatencyPoor)

	return testRes
}

func infraInternetDownloadSpeedTest(ctx context.Context, conf *testInfraConfig) testResult {
	testRes := testResult{Name: "InternetDownloadSpeed"}

	server, err := fetchOoklaServer(ctx, conf)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	log.Info(ctx, "Testing internet download speed...",
		z.Any("server_name", server.Name),
		z.Any("server_country", server.Country),
		z.Any("server_distance_km", server.Distance),
		z.Any("server_id", server.ID),
	)
	err = server.DownloadTestContext(ctx)
	if err != nil {
		return failedTestResult(testRes, err)
	}
	downloadSpeed := server.DLSpeed.Mbps()

	if downloadSpeed < internetDownloadSpeedMbpsPoor {
		testRes.Verdict = testVerdictPoor
	} else if downloadSpeed < internetDownloadSpeedMbpsAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = strconv.FormatFloat(downloadSpeed, 'f', 2, 64) + "MB/s"

	return testRes
}

func infraInternetUploadSpeedTest(ctx context.Context, conf *testInfraConfig) testResult {
	testRes := testResult{Name: "InternetUploadSpeed"}

	server, err := fetchOoklaServer(ctx, conf)
	if err != nil {
		return failedTestResult(testRes, err)
	}

	log.Info(ctx, "Testing internet upload speed...",
		z.Any("server_name", server.Name),
		z.Any("server_country", server.Country),
		z.Any("server_distance_km", server.Distance),
		z.Any("server_id", server.ID),
	)
	err = server.UploadTestContext(ctx)
	if err != nil {
		return failedTestResult(testRes, err)
	}
	uploadSpeed := server.ULSpeed.Mbps()

	if uploadSpeed < internetUploadSpeedMbpsPoor {
		testRes.Verdict = testVerdictPoor
	} else if uploadSpeed < internetUploadSpeedMbpsAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = strconv.FormatFloat(uploadSpeed, 'f', 2, 64) + "MB/s"

	return testRes
}

// helper functions

// DiskTestTool is the interface for different tools used for testing the disk.
type DiskTestTool interface {
	CheckAvailability() error
	WriteSpeed(ctx context.Context, testFilePath string, blockSize int) (float64, error)
	WriteIOPS(ctx context.Context, testFilePath string, blockSize int) (float64, error)
	ReadSpeed(ctx context.Context, testFilePath string, blockSize int) (float64, error)
	ReadIOPS(ctx context.Context, testFilePath string, blockSize int) (float64, error)
}

type FioTestTool struct{}

func (FioTestTool) CheckAvailability() error {
	_, err := exec.LookPath("fio")
	if err != nil {
		return errFioNotFound
	}

	return nil
}

func (FioTestTool) WriteSpeed(ctx context.Context, testFilePath string, blockSize int) (float64, error) {
	out, err := fioCommand(ctx, testFilePath, blockSize, "write")
	if err != nil {
		return 0, errors.Wrap(err, string(out))
	}
	defer os.Remove(testFilePath)

	var fioRes fioResult
	err = json.Unmarshal(out, &fioRes)
	if err != nil {
		return 0, errors.Wrap(err, "unmarshal fio result")
	}

	// jobs are grouped, so we pick the first and only one
	// bw (bandwidth) is in KB, convert it to MB
	diskWriteMBs := fioRes.Jobs[0].Write.Bw / 1024

	return diskWriteMBs, nil
}

func (FioTestTool) WriteIOPS(ctx context.Context, testFilePath string, blockSize int) (float64, error) {
	out, err := fioCommand(ctx, testFilePath, blockSize, "write")
	if err != nil {
		return 0, errors.Wrap(err, string(out))
	}
	defer os.Remove(testFilePath)

	var fioRes fioResult
	err = json.Unmarshal(out, &fioRes)
	if err != nil {
		return 0, errors.Wrap(err, "unmarshal fio result")
	}

	// jobs are grouped, so we pick the first and only one
	diskWriteIOPS := fioRes.Jobs[0].Write.Iops

	return diskWriteIOPS, nil
}

func (FioTestTool) ReadSpeed(ctx context.Context, testFilePath string, blockSize int) (float64, error) {
	out, err := fioCommand(ctx, testFilePath, blockSize, "read")
	if err != nil {
		return 0, errors.Wrap(err, string(out))
	}
	defer os.Remove(testFilePath)

	var fioRes fioResult
	err = json.Unmarshal(out, &fioRes)
	if err != nil {
		return 0, errors.Wrap(err, "unmarshal fio result")
	}

	// jobs are grouped, so we pick the first and only one
	// bw (bandwidth) is in KB, convert it to MB
	diskReadMBs := fioRes.Jobs[0].Read.Bw / 1024

	return diskReadMBs, nil
}

func (FioTestTool) ReadIOPS(ctx context.Context, testFilePath string, blockSize int) (float64, error) {
	out, err := fioCommand(ctx, testFilePath, blockSize, "read")
	if err != nil {
		return 0, errors.Wrap(err, string(out))
	}
	defer os.Remove(testFilePath)

	var fioRes fioResult
	err = json.Unmarshal(out, &fioRes)
	if err != nil {
		return 0, errors.Wrap(err, "unmarshal fio result")
	}

	// jobs are grouped, so we pick the first and only one
	diskReadIOPS := fioRes.Jobs[0].Read.Iops

	return diskReadIOPS, nil
}

func fioCommand(ctx context.Context, filename string, blocksize int, operation string) ([]byte, error) {
	//nolint:gosec
	cmd, err := exec.CommandContext(ctx, "fio",
		"--name=fioTest",
		fmt.Sprintf("--filename=%v/fiotest", filename),
		fmt.Sprintf("--size=%vMb", diskOpsMBsTotal/diskOpsNumOfJobs),
		fmt.Sprintf("--blocksize=%vk", blocksize),
		fmt.Sprintf("--numjobs=%v", diskOpsNumOfJobs),
		fmt.Sprintf("--rw=%v", operation),
		"--direct=1",
		"--runtime=60s",
		"--group_reporting",
		"--output-format=json",
	).Output()
	if err != nil {
		return nil, errors.Wrap(err, "exec fio command")
	}

	err = os.Remove(fmt.Sprintf("%v/fiotest", filename))
	if err != nil {
		return nil, errors.Wrap(err, "delete fio test file")
	}

	return cmd, nil
}

func availableMemoryLinux(context.Context) (int64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, errors.Wrap(err, "open /proc/meminfo")
	}
	scanner := bufio.NewScanner(file)
	if scanner.Err() != nil {
		return 0, errors.Wrap(err, "new scanner")
	}

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "MemAvailable") {
			continue
		}
		splitText := strings.Split(line, ": ")
		kbs := strings.Trim(strings.Split(splitText[1], "kB")[0], " ")
		kbsInt, err := strconv.ParseInt(kbs, 10, 64)
		if err != nil {
			return 0, errors.Wrap(err, "parse MemAvailable int")
		}

		return kbsInt * 1024, nil
	}

	return 0, errors.New("memAvailable not found in /proc/meminfo")
}

func availableMemoryMacos(ctx context.Context) (int64, error) {
	pageSizeBytes, err := exec.CommandContext(ctx, "pagesize").Output()
	if err != nil {
		return 0, errors.Wrap(err, "run pagesize")
	}
	memorySizePerPage, err := strconv.ParseInt(strings.TrimSuffix(string(pageSizeBytes), "\n"), 10, 64)
	if err != nil {
		return 0, errors.Wrap(err, "parse memorySizePerPage int")
	}

	out, err := exec.CommandContext(ctx, "vm_stat").Output()
	if err != nil {
		return 0, errors.Wrap(err, "run vm_stat")
	}
	outBuf := bytes.NewBuffer(out)
	scanner := bufio.NewScanner(outBuf)
	if scanner.Err() != nil {
		return 0, errors.Wrap(err, "new scanner")
	}

	var pagesFree, pagesInactive, pagesSpeculative int64
	for scanner.Scan() {
		line := scanner.Text()
		splitText := strings.Split(line, ": ")

		var bytes int64
		var err error
		switch {
		case strings.Contains(splitText[0], "Pages free"):
			bytes, err = strconv.ParseInt(strings.Trim(strings.Split(splitText[1], ".")[0], " "), 10, 64)
			if err != nil {
				return 0, errors.Wrap(err, "parse Pages free int")
			}
			pagesFree = bytes
		case strings.Contains(splitText[0], "Pages inactive"):
			bytes, err = strconv.ParseInt(strings.Trim(strings.Split(splitText[1], ".")[0], " "), 10, 64)
			if err != nil {
				return 0, errors.Wrap(err, "parse Pages inactive int")
			}
			pagesInactive = bytes
		case strings.Contains(splitText[0], "Pages speculative"):
			bytes, err = strconv.ParseInt(strings.Trim(strings.Split(splitText[1], ".")[0], " "), 10, 64)
			if err != nil {
				return 0, errors.Wrap(err, "parse Pages speculative int")
			}
			pagesSpeculative = bytes
		}
	}

	return ((pagesFree + pagesInactive + pagesSpeculative) * memorySizePerPage), nil
}

func totalMemoryLinux(context.Context) (int64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, errors.Wrap(err, "open /proc/meminfo")
	}
	scanner := bufio.NewScanner(file)
	if scanner.Err() != nil {
		return 0, errors.Wrap(err, "new scanner")
	}

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "MemTotal") {
			continue
		}
		splitText := strings.Split(line, ": ")
		kbs := strings.Trim(strings.Split(splitText[1], "kB")[0], " ")
		kbsInt, err := strconv.ParseInt(kbs, 10, 64)
		if err != nil {
			return 0, errors.Wrap(err, "parse MemTotal int")
		}

		return kbsInt * 1024, nil
	}

	return 0, errors.New("memTotal not found in /proc/meminfo")
}

func totalMemoryMacos(ctx context.Context) (int64, error) {
	out, err := exec.CommandContext(ctx, "sysctl", "hw.memsize").Output()
	if err != nil {
		return 0, errors.Wrap(err, "run sysctl hw.memsize")
	}

	memSize := strings.TrimSuffix(strings.Split(string(out), ": ")[1], "\n")
	memSizeInt, err := strconv.ParseInt(memSize, 10, 64)
	if err != nil {
		return 0, errors.Wrap(err, "parse memSize int")
	}

	return memSizeInt, nil
}

func fetchOoklaServer(_ context.Context, conf *testInfraConfig) (speedtest.Server, error) {
	speedtestClient := speedtest.New()

	serverList, err := speedtestClient.FetchServers()
	if err != nil {
		return speedtest.Server{}, errors.Wrap(err, "fetch Ookla servers")
	}

	var targets speedtest.Servers

	if len(conf.InternetTestServersOnly) != 0 {
		for _, server := range serverList {
			if slices.Contains(conf.InternetTestServersOnly, server.Name) {
				targets = append(targets, server)
			}
		}
	}

	if len(conf.InternetTestServersExclude) != 0 {
		for _, server := range serverList {
			if !slices.Contains(conf.InternetTestServersExclude, server.Name) {
				targets = append(targets, server)
			}
		}
	}

	if targets == nil {
		targets = serverList
	}

	servers, err := targets.FindServer([]int{})
	if err != nil {
		return speedtest.Server{}, errors.Wrap(err, "find Ookla server")
	}

	return *servers[0], nil
}
