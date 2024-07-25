// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package stacksnipe

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

const (
	pollInterval = 15 * time.Second
)

// supportedVCs represents the process names to identify Ethereum validator stack processes.
var supportedVCs = map[string]struct{}{
	"lighthouse": {},
	"teku":       {},
	"nimbus":     {},
	"prysm":      {},
	"lodestar":   {},
}

// maybeVCs is the list of process names which might be running as interpreters for components of the
// Ethereum validator stack.
var maybeVCs = map[string]struct{}{
	// lodestar runs under node
	"node": {},
}

// StackComponent is a named process of the Ethereum validator stack running on the machine,
// whose CLI parameters (also called cmdline) is read from a /proc-like filesystem.
type StackComponent struct {
	Name      string
	CLIParams string
}

// Instance returns an instance of stacksnipe.
type Instance struct {
	procPath    string
	metricsFunc func([]string, []string)
	interval    time.Duration
}

// New returns a new Instance configured with the given /proc path and metrics export function.
func New(procPath string, metricFunc func([]string, []string)) Instance {
	return Instance{
		procPath:    procPath,
		metricsFunc: metricFunc,
		interval:    pollInterval,
	}
}

// NewWithInterval returns a new Instance configured with the given /proc path, metrics export function and the specified polling interval.
func NewWithInterval(procPath string, metricFunc func([]string, []string), interval time.Duration) Instance {
	return Instance{
		procPath:    procPath,
		metricsFunc: metricFunc,
		interval:    interval,
	}
}

// Run polls procPath every 15 seconds and exposes the results through the stack Prometheus metric.
func (i *Instance) Run(ctx context.Context) {
	ctx = log.WithTopic(ctx, "stacksnipe")

	if i.procPath == "" {
		log.Info(ctx, "Stack component sniping disabled")
		return
	}

	ticker := time.NewTicker(i.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			comp, err := snipe(ctx, i.procPath)
			if err != nil {
				log.Warn(ctx, "Failed to snipe stack components", err)
				continue
			}

			var (
				names     []string
				cliParams []string
			)

			for _, c := range comp {
				names = append(names, c.Name)
				cliParams = append(cliParams, c.CLIParams)
			}

			i.metricsFunc(names, cliParams)
		}
	}
}

// snipe reads /proc entries from procPath, looking for processes that look like Ethereum validator stack components.
func snipe(ctx context.Context, procPath string) ([]StackComponent, error) {
	var (
		wb      = make(chan StackComponent)
		ret     []StackComponent
		walkErr error
	)

	go func() {
		if err := filepath.WalkDir(procPath, walkFunc(ctx, wb)); err != nil {
			walkErr = errors.Wrap(err, "cannot walk proc path", z.Str("proc_path", procPath))
		}

		close(wb)
	}()

	for c := range wb {
		ret = append(ret, c)
	}

	if walkErr != nil {
		return nil, walkErr
	}

	return ret, nil
}

// walkFunc walks a /proc-like filesystem as invoked by filepath.WalkDir, and sends entries to wb.
func walkFunc(ctx context.Context, wb chan<- StackComponent) fs.WalkDirFunc {
	cmdlineDedup := make(map[string]struct{})

	return func(path string, d fs.DirEntry, err error) error {
		// ignore directory access error and don't walk the directory
		if err != nil {
			return nil //nolint:nilerr // best effort component
		}

		// ignore files
		if !d.IsDir() {
			return nil
		}

		// ignore directories which don't look like pids
		hostPID, err := strconv.ParseUint(d.Name(), 10, 64)
		if err != nil {
			return nil //nolint:nilerr // best effort component
		}

		// do initial filtering by process' comm
		commBytes, err := os.ReadFile(filepath.Join(path, "comm"))
		if err != nil {
			// ignore error, best effort
			return nil //nolint:nilerr // best effort component
		}

		comm := strings.TrimSpace(string(commBytes))
		_, vcOk := supportedVCs[comm]
		_, maybeVCOk := maybeVCs[comm]

		if !vcOk && !maybeVCOk {
			return nil
		}

		// grab vc's cmdline
		cmdlineBytes, err := os.ReadFile(filepath.Join(path, "cmdline"))
		if err != nil {
			// ignore error, best effort
			return nil //nolint:nilerr // best effort component
		}

		cmdlineString := string(cmdlineBytes)

		cmdlineSplit := bytes.Split(cmdlineBytes, []byte{0})

		var vcName string
		for vc := range supportedVCs {
			if strings.Contains(cmdlineString, vc) {
				vcName = vc
			}
		}

		if vcName == "" {
			return nil
		}

		if _, ok := cmdlineDedup[cmdlineString]; ok {
			// we already have seen this, probably a background thread
			return nil
		}

		cmdlineDedup[cmdlineString] = struct{}{}

		var cmdLine []string
		for _, cl := range cmdlineSplit {
			if len(cl) == 0 {
				continue
			}

			cmdLine = append(cmdLine, string(cl))
		}

		if len(cmdLine) == 0 {
			// no cmdline, ignore
			return nil
		}

		cmdLineStr := strings.Join(cmdLine, " ")

		log.Debug(ctx, "Detected stack component", z.Str("name", vcName), z.U64("host_pid", hostPID), z.Str("cmdline", cmdLineStr))

		wb <- StackComponent{
			Name:      vcName,
			CLIParams: cmdLineStr,
		}

		return nil
	}
}
