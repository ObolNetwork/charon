// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pidfile

import (
	"os"
	"path/filepath"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

const (
	filename = "charon-pidfile"
)

// New creates a pidfile called "charon-pidfile" in dataDir, writing contextStr in it.
// If a pidfile exists already in dataDir New returns an error, a clean-up function otherwise.
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

	return func() error {
		if err := os.Remove(path); err != nil {
			return errors.Wrap(err, "cannot remove pidfile")
		}

		return nil
	}, nil
}
