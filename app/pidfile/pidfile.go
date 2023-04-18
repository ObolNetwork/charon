// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pidfile

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

const (
	filename = "charon-pidfile"
)

// New creates a pidfile called "charon-pidfile" in dataDir, writing contextStr in it.
// If a pidfile exists already in dataDir New returns an error, a clean-up function otherwise.
// New also registers a SIGINT signal handler so that it cleans its state if CTRL-C is called.
func New(dataDir, contextStr string) (func() error, error) {
	pfPath := filepath.Join(dataDir, filename)

	if _, err := os.Stat(pfPath); err == nil {
		readCtxStr, err := os.ReadFile(pfPath)
		if err != nil {
			return nil, errors.Wrap(err, "could not read pidfile content even if present")
		}

		return nil, errors.New(
			"another instance of charon is running on the selected data directory",
			z.Str("data_directory", dataDir),
			z.Str("context", string(readCtxStr)),
		)
	} else if errors.Is(err, os.ErrNotExist) {
		return createPidfile(pfPath, contextStr)
	} else {
		return nil, errors.Wrap(err, "fatal error while handling pidfile", z.Str("path", pfPath))
	}
}

func createPidfile(path, contextStr string) (func() error, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create pidfile", z.Str("path", path))
	}

	amt, err := f.WriteString(contextStr)
	if err != nil {
		return nil, errors.Wrap(err, "cannot write context string in pidfile", z.Str("path", path))
	}

	if amt != len(contextStr) {
		return nil, errors.New(
			"could not write entirety of context string in pidfile",
			z.Str("path", path),
			z.Int("expected", len(contextStr)),
			z.Int("got", amt),
		)
	}

	alreadyDeleted := atomic.Bool{}
	alreadyDeleted.Store(false)

	ctx := context.Background()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c

		defer os.Exit(0)

		if alreadyDeleted.Load() {
			log.Debug(ctx, "Pidfile already deleted, not deleting from ctrl-c handler")
			return
		}

		alreadyDeleted.Store(true)

		log.Debug(ctx, "Deleting pidfile from SIGINT")
		if err := os.Remove(path); err != nil {
			log.Error(ctx, "Cannot delete pidfile", err)
			return
		}
	}()

	return func() error {
		if alreadyDeleted.Load() {
			log.Debug(ctx, "Pidfile already deleted, not deleting from closure")
			return nil
		}

		alreadyDeleted.Store(true)

		if err := os.Remove(path); err != nil {
			return errors.Wrap(err, "cannot remove pidfile")
		}

		return nil
	}, nil
}
