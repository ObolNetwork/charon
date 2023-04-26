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

// staleDuration is the duration after which a private key lock file is considered stale.
var staleDuration = 5 * time.Second

// New returns new private key locking service. It errors if a recently-updated private key lock file exits.
func New(path, command string) (Service, error) {
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) { //nolint:revive // Empty block is fine.
		// No file, we will create it in run
	} else if err != nil {
		return Service{}, errors.Wrap(err, "cannot read private key lock file", z.Str("path", path))
	} else {
		var meta metadata
		if err := json.Unmarshal(content, &meta); err != nil {
			return Service{}, errors.Wrap(err, "cannot decode private key lock file content", z.Str("path", path))
		}

		if time.Since(meta.Timestamp) <= staleDuration {
			return Service{}, errors.New(
				"existing private key lock file found, another charon instance may be running on your machine",
				z.Str("path", path),
				z.Str("command", meta.Command),
			)
		}
	}

	return Service{
		command: command,
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

	// Immediately write lockfile
	if err := writeFile(h.path, h.command, time.Now()); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			if err := os.Remove(h.path); err != nil {
				return errors.Wrap(err, "deleting private key lock file failed")
			}

			return nil
		case <-tick.C:
			// Overwrite lockfile with new metadata
			if err := writeFile(h.path, h.command, time.Now()); err != nil {
				return err
			}
		}
	}
}

// metadata is the metadata stored in the lock file.
type metadata struct {
	Command   string    `json:"command"`
	Timestamp time.Time `json:"timestamp"`
}

// writeFile creates or updates the file with the latest metadata.
func writeFile(path, command string, now time.Time) error {
	b, err := json.Marshal(metadata{Command: command, Timestamp: now})
	if err != nil {
		return errors.Wrap(err, "cannot marshal private key lock file")
	}

	//nolint:gosec // Readable and writable for all users is fine for this file.
	if err := os.WriteFile(path, b, 0o666); err != nil {
		return errors.Wrap(err, "cannot write private key lock file", z.Str("path", path))
	}

	return nil
}
