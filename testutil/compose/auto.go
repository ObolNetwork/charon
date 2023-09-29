// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package compose

import (
	"context"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

type AutoConfig struct {
	// Dir is the directory to use for compose artifacts.
	Dir string
	// AlertTimeout is the timeout to collect alerts before shutdown. Zero disables timeout.
	AlertTimeout time.Duration
	// SudoPerms enables changing all compose artefacts file permissions using sudo.
	SudoPerms bool
	// Print generated docker-compose.yml files.
	PrintYML bool
	// RunTmplFunc allows arbitrary overrides in the run step template.
	RunTmplFunc func(*TmplData)
	// DefineTmplFunc allows arbitrary overrides if the define step template.
	DefineTmplFunc func(*TmplData)
	// LogFile enables writing (appending) docker-compose output to this file path instead of stdout.
	LogFile string
}

// Auto runs all three steps (define,lock,run) sequentially with support for detecting alerts.
func Auto(ctx context.Context, conf AutoConfig) error {
	ctx = log.WithTopic(ctx, "auto")

	w, closeFunc, err := newLogWriter(conf.LogFile)
	if err != nil {
		return err
	}
	defer closeFunc() //nolint:errcheck // non-critical

	steps := []struct {
		Name     string
		RunFunc  RunFunc
		TmplFunc func(*TmplData)
		RunStep  bool
	}{
		{
			Name:     "define",
			RunFunc:  Define,
			TmplFunc: conf.DefineTmplFunc,
		}, {
			Name:    "lock",
			RunFunc: Lock,
		}, {
			Name:     "run",
			RunFunc:  Run,
			TmplFunc: conf.RunTmplFunc,
			RunStep:  true,
		},
	}

	for _, step := range steps {
		run := NewRunnerFunc(step.Name, conf.Dir, false, step.RunFunc)
		tmpl, err := run(ctx)
		if err != nil {
			return err
		}

		if conf.SudoPerms {
			if err := fixPerms(ctx, conf.Dir); err != nil {
				return err
			}
		}

		if step.TmplFunc != nil {
			step.TmplFunc(&tmpl)
			err := WriteDockerCompose(conf.Dir, tmpl)
			if err != nil {
				return err
			}
		}

		if conf.PrintYML {
			if err := printDockerCompose(ctx, conf.Dir); err != nil {
				return err
			}
		}

		if step.RunStep { // Continue below if final run step.
			break
		}

		_, _ = w.Write([]byte("===== " + step.Name + " step: docker-compose up =====\n"))

		if err := execUp(ctx, conf.Dir, w); err != nil {
			return err
		}
	}

	// Ensure everything is clean before we start with alert test.
	_ = execDown(ctx, conf.Dir)

	_, _ = w.Write([]byte("===== run step: docker-compose up --no-start --build =====\n"))

	// Build and create docker-compose services before executing docker-compose up.
	if err = execBuildAndCreate(ctx, conf.Dir); err != nil {
		return err
	}

	if conf.AlertTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, conf.AlertTimeout)
		defer cancel()
	}

	alerts := startAlertCollector(ctx, conf.Dir)

	defer func() {
		_ = execDown(context.Background(), conf.Dir)
	}()

	_, _ = w.Write([]byte("===== run step: docker-compose up =====\n"))

	if err = execUp(ctx, conf.Dir, w); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	var (
		alertMsgs    []string
		alertSuccess bool
	)
	for alert := range alerts {
		if alert == alertsPolled {
			alertSuccess = true
		} else {
			alertMsgs = append(alertMsgs, alert)
		}
	}
	if !alertSuccess {
		return errors.New("alerts couldn't be polled")
	} else if len(alertMsgs) > 0 {
		return errors.New("alerts detected", z.Any("alerts", alertMsgs))
	}

	log.Info(ctx, "No alerts detected")

	return nil
}

// printDockerCompose prints the docker-compose.yml file to stdout.
func printDockerCompose(ctx context.Context, dir string) error {
	log.Info(ctx, "Printing docker-compose.yml")
	cmd := exec.CommandContext(ctx, "cat", "docker-compose.yml")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return errors.Wrap(err, "exec cat docker-compose.yml")
	}

	return nil
}

// fixPerms fixes file permissions as a workaround for linux docker by removing
// all restrictions using sudo chmod.
func fixPerms(ctx context.Context, dir string) error {
	cmd := exec.CommandContext(ctx, "sudo", "chmod", "-R", "a+wrX", ".")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return errors.Wrap(err, "exec sudo chmod")
	}

	return nil
}

// execDown executes `docker-compose down`.
func execDown(ctx context.Context, dir string) error {
	log.Info(ctx, "Executing docker-compose down")

	cmd := exec.CommandContext(ctx, "docker compose", "down",
		"--remove-orphans",
		"--timeout=2",
	)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return errors.Wrap(err, "run down")
	}

	return nil
}

// execUp executes `docker-compose up` and it writes docker compose logs to the given out io.Writer.
func execUp(ctx context.Context, dir string, out io.Writer) error {
	// Build first so containers start at the same time below.
	log.Info(ctx, "Executing docker-compose build")
	cmd := exec.CommandContext(ctx, "docker-compose", "build", "--parallel")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.Wrap(err, "exec docker-compose build", z.Str("output", string(out)))
	}

	log.Info(ctx, "Executing docker-compose up")
	cmd = exec.CommandContext(ctx, "docker-compose", "up",
		"--remove-orphans",
		"--abort-on-container-exit",
		"--quiet-pull",
	)
	cmd.Dir = dir
	cmd.Stdout = out
	cmd.Stderr = out

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}

		return errors.Wrap(err, "exec docker-compose up")
	}

	return nil
}

// execBuildAndCreate builds and creates containers. It should be called before execUp for run step.
func execBuildAndCreate(ctx context.Context, dir string) error {
	log.Info(ctx, "Executing docker-compose up --no-start --build")
	cmd := exec.CommandContext(ctx, "docker compose", "up", "--no-start", "--build")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.Wrap(err, "exec docker compose up --no-start --build", z.Str("output", string(out)))
	}

	return nil
}

// RunFunc defines a function that generates docker-compose.yml from config and returns the template data.
type RunFunc func(context.Context, string, Config) (TmplData, error)

// NewRunnerFunc returns a function that wraps and runs a run function.
func NewRunnerFunc(topic string, dir string, up bool, runFunc RunFunc,
) func(ctx context.Context) (data TmplData, err error) {
	return func(ctx context.Context) (data TmplData, err error) {
		ctx = log.WithTopic(ctx, topic)

		conf, err := LoadConfig(dir)
		if errors.Is(err, fs.ErrNotExist) {
			return TmplData{}, errors.New("compose config.json not found; maybe try `compose new` first", z.Str("dir", dir))
		} else if err != nil {
			return TmplData{}, err
		}

		log.Info(ctx, "Running compose command", z.Str("command", topic))

		data, err = runFunc(ctx, dir, conf)
		if err != nil {
			return TmplData{}, err
		}

		if up {
			return data, execUp(ctx, dir, os.Stdout)
		}

		return data, nil
	}
}

// newLogWriter returns io writer and a close function or an error.
func newLogWriter(logFile string) (io.WriteCloser, func() error, error) {
	if logFile == "" {
		return os.Stdout, func() error { return nil }, nil
	}

	// Preparing log file.
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) //nolint:nosnakecase
	if err != nil {
		return nil, nil, errors.Wrap(err, "open log file")
	}

	return file, file.Close, nil
}
