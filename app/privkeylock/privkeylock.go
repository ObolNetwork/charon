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

// New returns new private key locking service. It errors if a recently-updated private key lock file exits.
func New(path, contextStr string) (Service, error) {
	if content, err := os.ReadFile(path); errors.Is(err, os.ErrNotExist) {
		// No file, we will create it in run
	} else if err != nil {
		return Service{}, errors.Wrap(err, "cannot read private key lock file", z.Str("path", path))
	} else {
		var meta metadata
		if err := json.Unmarshal(content, &meta); err != nil {
			return Service{}, errors.Wrap(err, "cannot decode private key lock file content", z.Str("path", path))
		}

		if time.Since(meta.Timestamp) <= staleDuration() {
			return Service{}, errors.New(
				"existing private key lock file found, another charon instance may be running on your machine",
				z.Str("path", path),
				z.Str("command", meta.Command),
			)
		}
	}

	return Service{
		command: contextStr,
		path:    path,
	}, nil
}

// Service is a private key locking service.
type Service struct {
	command string
	path    string
}

// Run runs the service, updating the lock file every second and deleting it on context cancellation.
func (h Service) Run(ctx context.Context) error {
	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			if err := os.Remove(h.path); err != nil {
				return errors.Wrap(err, "deleting private key lock file failed")
			}

			return nil
		case <-tick.C:
			// Overwrite lockfile with new metadata
			if err := writeFile(h.path, h.command); err != nil {
				return err
			}
		}
	}
}

// staleDuration is the time after which a lockfile is considered stale.
var staleDuration = func() time.Duration {
	return 5 * time.Second
}

// nowFunc returns the current time. It is aliased for testing.
var nowFunc = time.Now

// metadata is the metadata stored in the lock file.
type metadata struct {
	Command   string
	Timestamp time.Time
}

// writeFile creates or updates the file with the latest metadata.
func writeFile(path, command string) error {
	b, err := json.Marshal(metadata{Command: command, Timestamp: nowFunc()})
	if err != nil {
		return errors.Wrap(err, "cannot marshal private key lock file")
	}

	//nolint:gosec // Readable and writable for all users is fine for this file.
	if err := os.WriteFile(path, b, 0o666); err != nil {
		return errors.Wrap(err, "cannot write private key lock file", z.Str("path", path))
	}

	return nil
}
