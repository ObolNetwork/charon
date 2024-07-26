// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/showwin/speedtest-go/speedtest"
	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"
	"golang.org/x/sys/unix"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

type testPerformanceConfig struct {
	testConfig
	DiskWriteMB                int
	InternetTestServersOnly    []string
	InternetTestServersExclude []string
}

const (
	diskWriteLoops               = 5
	diskWriteMBsAvg              = 1000
	diskWriteMBsBad              = 500
	availableMemoryMBsAvg        = 4000
	availableMemoryMBsBad        = 2000
	totalMemoryMBsAvg            = 8000
	totalMemoryMBsBad            = 4000
	internetLatencyAvg           = 20 * time.Millisecond
	internetLatencyBad           = 50 * time.Millisecond
	internetDownloadSpeedMbpsAvg = 50
	internetDownloadSpeedMbpsBad = 15
	internetUploadSpeedMbpsAvg   = 50
	internetUploadSpeedMbpsBad   = 15
)

func newTestPerformanceCmd(runFunc func(context.Context, io.Writer, testPerformanceConfig) error) *cobra.Command {
	var config testPerformanceConfig

	cmd := &cobra.Command{
		Use:   "performance",
		Short: "Run multiple hardware and connectivity performance tests",
		Long:  `Run multiple hardware and connectivity performance tests. Verify that Charon is running on host with sufficient capabilities.`,
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
	cmd.Flags().StringSliceVar(&config.InternetTestServersOnly, "internet-test-servers-only", []string{}, "List of server names to be included for the tests, the best performing one is chosen.")
	cmd.Flags().StringSliceVar(&config.InternetTestServersExclude, "internet-test-servers-exclude", []string{}, "List of server names to be excluded from the tests.")
}

func supportedPerformanceTestCases() map[testCaseName]func(context.Context, *testPerformanceConfig) testResult {
	return map[testCaseName]func(context.Context, *testPerformanceConfig) testResult{
		{name: "diskWrite", order: 1}:             performanceDiskWriteTest,
		{name: "availableMemory", order: 2}:       performanceAvailableMemoryTest,
		{name: "totalMemory", order: 3}:           performanceTotalMemoryTest,
		{name: "internetLatency", order: 4}:       performanceInternetLatencyTest,
		{name: "internetDownloadSpeed", order: 5}: performanceInternetDownloadSpeedTest,
		{name: "internetUploadSpeed", order: 6}:   performanceInternetUploadSpeedTest,
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
	wd, _ := os.UserHomeDir()
	err := unix.Statfs(wd, &stat)
	if err != nil {
		return failedTestResult(testRes, err)
	}
	// Available blocks * size per block = available space in bytes; remove 20% for safety
	availableMB := int(stat.Bavail*uint64(stat.Bsize)/1024/1024) / 5 * 4
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
	ex, err := os.UserHomeDir()
	if err != nil {
		return 0, errors.Wrap(err, "os executable write file")
	}
	fName := ex + `/diskio`
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

func performanceAvailableMemoryTest(ctx context.Context, _ *testPerformanceConfig) testResult {
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

	if availableMemoryMB < availableMemoryMBsBad {
		testRes.Verdict = testVerdictBad
	} else if availableMemoryMB < availableMemoryMBsAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = strconv.Itoa(int(availableMemoryMB)) + "MB"

	return testRes
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

func performanceTotalMemoryTest(ctx context.Context, _ *testPerformanceConfig) testResult {
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

	if totalMemoryMB < totalMemoryMBsBad {
		testRes.Verdict = testVerdictBad
	} else if totalMemoryMB < totalMemoryMBsAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = strconv.Itoa(int(totalMemoryMB)) + "MB"

	return testRes
}

func fetchOoklaServer(_ context.Context, conf *testPerformanceConfig) (speedtest.Server, error) {
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
		var targets speedtest.Servers
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

func performanceInternetLatencyTest(ctx context.Context, conf *testPerformanceConfig) testResult {
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
	latency := server.Latency

	if latency > internetLatencyBad {
		testRes.Verdict = testVerdictBad
	} else if latency > internetLatencyAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = latency.Round(time.Microsecond).String()

	return testRes
}

func performanceInternetDownloadSpeedTest(ctx context.Context, conf *testPerformanceConfig) testResult {
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

	if downloadSpeed < internetDownloadSpeedMbpsBad {
		testRes.Verdict = testVerdictBad
	} else if downloadSpeed < internetDownloadSpeedMbpsAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = strconv.FormatFloat(downloadSpeed, 'f', 2, 64) + "MB/s"

	return testRes
}

func performanceInternetUploadSpeedTest(ctx context.Context, conf *testPerformanceConfig) testResult {
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

	if uploadSpeed < internetUploadSpeedMbpsBad {
		testRes.Verdict = testVerdictBad
	} else if uploadSpeed < internetUploadSpeedMbpsAvg {
		testRes.Verdict = testVerdictAvg
	} else {
		testRes.Verdict = testVerdictGood
	}
	testRes.Measurement = strconv.FormatFloat(uploadSpeed, 'f', 2, 64) + "MB/s"

	return testRes
}
