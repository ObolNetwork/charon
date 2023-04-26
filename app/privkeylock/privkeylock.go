// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package privkeylock

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

var lockfileGracePeriod = func() time.Duration {
	return 5 * time.Second
}

var timestampFunc = time.Now

type metadata struct {
	ContextStr string
	Timestamp  time.Time
}

func newLockCtx(contextStr string) metadata {
	return metadata{
		ContextStr: contextStr,
		Timestamp:  timestampFunc(),
	}
}

// Service contains the necessary fields to lock the private key file periodically.
// It also contains the Clean function, which must be called by callers to remove the private key
// lock once a graceful shutdown phase is reached.
type Service struct {
	command string
	path    string

	clean func() error
}

// Run updates the lock file pointed by the path once every second.
// It must be run asynchronously.
func (h Service) Run(ctx context.Context) error {
	tick := time.NewTicker(1 * time.Second)

	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():

			if err := h.clean(); err != nil {
				return errors.Wrap(err, "cannot delete private key lock file")
			}

			return nil
		case <-tick.C:
			if err := os.Remove(h.path); err != nil {
				return errors.Wrap(err,
					"could not remove old lock file whose timestamp is past grace period",
					z.Str("path", h.path),
					z.Str("context", h.command),
				)
			}

			// safety time has passed, overwrite lockfile with our own data
			if err := createPrivkeyLock(h.path, h.command); err != nil {
				return errors.Wrap(err,
					"cannot create private key lock file, manually delete file at path to continue with execution",
					z.Str("path", h.path),
					z.Str("context", h.command),
				)
			}
		}
	}
}

// New creates a private key lock file in path, writing ContextStr in it.
// If a private key lock file exists at path New returns an error, a Service otherwise.
func New(path, contextStr string) (Service, error) {
	if fileContent, err := os.ReadFile(path); err == nil {
		lctx := metadata{}
		if err := json.Unmarshal(fileContent, &lctx); err != nil {
			return Service{}, errors.Wrap(err, "cannot decode private key lock file content")
		}

		if time.Since(lctx.Timestamp) <= lockfileGracePeriod() {
			return Service{}, errors.New(
				"existing private key lock file found, another charon instance may be running on your machine, if not then you can delete that file",
				z.Str("path", path),
				z.Str("context", lctx.ContextStr),
			)
		}

		return Service{
			command: contextStr,
			path:    path,
			clean:   defaultCleanupFunc(path),
		}, nil
	} else if errors.Is(err, os.ErrNotExist) {
		if err := createPrivkeyLock(path, contextStr); err != nil {
			return Service{}, err
		}

		return Service{
			command: contextStr,
			path:    path,
			clean:   defaultCleanupFunc(path),
		}, nil
	} else {
		return Service{}, errors.Wrap(err, "fatal error while handling private key lock file", z.Str("path", path))
	}
}

func defaultCleanupFunc(path string) func() error {
	return func() error {
		if err := os.Remove(path); err != nil {
			return errors.Wrap(err, "cannot remove private key lock file")
		}

		return nil
	}
}

// createPrivkeyLock creates a file in path with ContextStr and a timestamp written inside.
// It's an overzealous function: if it can't write exactly len(ContextStr, timestamp) bytes in path,
// it returns error.
func createPrivkeyLock(path, contextStr string) error {
	lctx := newLockCtx(contextStr)
	content, err := json.Marshal(lctx)
	if err != nil {
		return errors.Wrap(err, "cannot marshal private key lock context")
	}

	//nolint:gosec // non-sensible file
	if err := os.WriteFile(path, content, 0o655); err != nil {
		return errors.Wrap(err, "cannot write context string in private key lock file", z.Str("path", path))
	}

	return nil
}
