// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package privkeylock

import (
	"encoding/json"
	"os"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

var (
	// staleDuration is the duration after which a private key lock file is considered stale.
	staleDuration = 5 * time.Second

	// updatePeriod is the duration after which the private key lock file is updated.
	updatePeriod = 1 * time.Second
)

// New returns new private key locking service. It errors if a recently-updated private key lock file exists.
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

	if err := writeFile(path, command, time.Now()); err != nil {
		return Service{}, err
	}

	return Service{
		command:      command,
		path:         path,
		updatePeriod: updatePeriod,
		quit:         make(chan struct{}),
		done:         make(chan struct{}),
	}, nil
}

// Service is a private key locking service.
type Service struct {
	command      string
	path         string
	updatePeriod time.Duration
	quit         chan struct{} // Quit exits the Run goroutine if closed.
	done         chan struct{} // Done is closed when Run exits, which exits the Close goroutine.
}

// Run runs the service, updating the lock file every second and deleting it on context cancellation.
func (s Service) Run() error {
	defer close(s.done)

	tick := time.NewTicker(s.updatePeriod)
	defer tick.Stop()

	for {
		select {
		case <-s.quit:
			if err := os.Remove(s.path); err != nil {
				return errors.Wrap(err, "deleting private key lock file failed")
			}

			return nil
		case <-tick.C:
			// Overwrite lockfile with new metadata
			if err := writeFile(s.path, s.command, time.Now()); err != nil {
				return err
			}
		}
	}
}

// Close closes the service, waiting for the Run goroutine to exit.
// Note this will block forever if Run is not called.
func (s Service) Close() {
	close(s.quit)
	<-s.done
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
