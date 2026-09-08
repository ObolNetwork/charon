// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package stacksnipe

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
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
	"vouch":      {},
}

// maybeVCs is the list of process names which might be running as interpreters for components of the
// Ethereum validator stack.
var maybeVCs = map[string]struct{}{
	// lodestar runs under node
	"node": {},
}

// sensitiveFlagFragments are the flag name fragments whose values must never leave the process.
// Validator client command lines routinely carry keystore passwords, keymanager bearer tokens and
// the paths of files holding them, none of which belong in a metric label or a log line.
var sensitiveFlagFragments = []string{
	"auth",
	"jwt",
	"key",
	"mnemonic",
	"passphrase",
	"password",
	"secret",
	"token",
}

// redactedValue replaces the value of a sensitive flag in an exported command line.
const redactedValue = "<redacted>"

// basicAuthRe matches the userinfo of a URL so a credential embedded in an otherwise innocuous
// flag value (e.g. https://user:pass@host) is redacted while the scheme, user and host stay visible.
var basicAuthRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^:@/?#\s]+):[^@/?#\s]+@`)

// queryParamRe matches a single URL query parameter so sensitive ones (?token=..., &jwt=...)
// can be redacted by name while the rest of the value is preserved.
var queryParamRe = regexp.MustCompile(`([?&])([^=&#\s]+)=([^&#\s]*)`)

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

	log.Warn(ctx, "Stack component sniping enabled: command lines of detected validator clients are exported "+
		"to the monitoring endpoint and debug logs, with the values of secret-shaped flags redacted", nil,
		z.Str("proc_directory", i.procPath))

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

// isSensitiveFlag reports whether name looks like a flag whose value carries secret material.
func isSensitiveFlag(name string) bool {
	name = strings.ToLower(strings.TrimLeft(name, "-"))

	for _, fragment := range sensitiveFlagFragments {
		if strings.Contains(name, fragment) {
			return true
		}
	}

	return false
}

// redactValue scrubs secret material embedded inside a value that a flag name check misses:
// basic-auth credentials in a URL and the values of sensitive query parameters. The rest of the
// value (scheme, host, path, innocuous parameters) is preserved so telemetry stays useful.
func redactValue(value string) string {
	value = basicAuthRe.ReplaceAllString(value, "${1}:"+redactedValue+"@")

	value = queryParamRe.ReplaceAllStringFunc(value, func(param string) string {
		groups := queryParamRe.FindStringSubmatch(param)
		if groups[3] != "" && isSensitiveFlag(groups[2]) {
			return groups[1] + groups[2] + "=" + redactedValue
		}

		return param
	})

	return value
}

// splitCmdlineBlob tokenises a whole command line that arrived as a single blob, honouring single
// and double quotes so a quoted value containing spaces stays one argument (and is redacted whole)
// rather than being split into leaking fragments.
func splitCmdlineBlob(blob string) []string {
	var (
		tokens []string
		cur    strings.Builder
		quote  rune
		inTok  bool
	)

	flush := func() {
		if inTok {
			tokens = append(tokens, cur.String())
			cur.Reset()

			inTok = false
		}
	}

	for _, r := range blob {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}

			inTok = true
		case r == '\'' || r == '"':
			quote = r
			inTok = true
		case r == ' ' || r == '\t':
			flush()
		default:
			cur.WriteRune(r)

			inTok = true
		}
	}

	flush()

	return tokens
}

// redactCmdline redacts the value of every sensitive flag while keeping flag names and innocuous
// values, so the exported command line stays diagnostically useful. It covers the "--flag value"
// and "--flag=value" forms, secrets embedded in a URL value of an innocuous flag (see redactValue),
// and values beginning with "-". Args are normally the NUL separated /proc elements; a whole command
// line handed over as one blob is tokenised (see splitCmdlineBlob) and its sensitive values redacted
// greedily, so redaction fails safe rather than leaking.
func redactCmdline(args []string) []string {
	greedy := false

	if len(args) == 1 && strings.ContainsAny(args[0], " \t") {
		args = splitCmdlineBlob(args[0])
		greedy = true
	}

	redacted := make([]string, 0, len(args))

	var (
		redactNext   bool // the following token(s) are the value of a sensitive flag
		valueEmitted bool // the single marker for that value has already been appended
	)

	for _, arg := range args {
		if redactNext {
			// A long flag means the sensitive flag took no value; stop redacting and reprocess
			// this token as a flag. Anything else is (part of) the value.
			if !strings.HasPrefix(arg, "--") {
				if !valueEmitted {
					redacted = append(redacted, redactedValue)
					valueEmitted = true
				}

				// A NUL separated cmdline gives one value per flag; only the ambiguous blob
				// fallback keeps consuming tokens into the same value.
				if !greedy {
					redactNext = false
				}

				continue
			}

			redactNext = false
		}

		if !strings.HasPrefix(arg, "-") {
			redacted = append(redacted, redactValue(arg))
			continue
		}

		name, value, hasValue := strings.Cut(arg, "=")
		if !isSensitiveFlag(name) {
			if hasValue {
				redacted = append(redacted, name+"="+redactValue(value))
			} else {
				redacted = append(redacted, arg)
			}

			continue
		}

		if hasValue {
			redacted = append(redacted, name+"="+redactedValue)
			continue
		}

		redactNext = true
		valueEmitted = false

		redacted = append(redacted, arg)
	}

	return redacted
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

		cmdLineStr := strings.Join(redactCmdline(cmdLine), " ")

		log.Debug(ctx, "Detected stack component", z.Str("name", vcName), z.U64("host_pid", hostPID), z.Str("cmdline", cmdLineStr))

		wb <- StackComponent{
			Name:      vcName,
			CLIParams: cmdLineStr,
		}

		return nil
	}
}
