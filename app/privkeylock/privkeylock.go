// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package privkeylock

import (
	"encoding/json"
	"fmt"
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

	// gracePeriod is the duration after which a new cluster (new lock hash) can be run after an edit command.
	// (we can't use chain spec at this time, so we use fixed duration of 768 seconds)
	gracePeriod = 2 * 32 * 12 * time.Second
)

// New returns new private key locking service. It errors if a recently-updated private key lock file exists.
func New(privKeyFilePath, clusterLockFilePath, command string) (Service, error) {
	clusterLockHash, err := readClusterLockHash(clusterLockFilePath)
	if err != nil {
		return Service{}, err
	}

	privKeyFilePath += ".lock"

	content, err := os.ReadFile(privKeyFilePath)
	if errors.Is(err, os.ErrNotExist) { //nolint:revive // Empty block is fine.
		// No file, we will create it in run
	} else if err != nil {
		return Service{}, errors.Wrap(err, "read private key lock file", z.Str("path", privKeyFilePath))
	} else {
		var meta metadata
		if err := json.Unmarshal(content, &meta); err != nil {
			return Service{}, errors.Wrap(err, "decode private key lock file", z.Str("path", privKeyFilePath))
		}

		if time.Since(meta.Timestamp) <= staleDuration {
			return Service{}, errors.New(
				"existing private key lock file found, another charon instance may be running on your machine",
				z.Str("path", privKeyFilePath),
				z.Str("command", meta.Command),
				z.Str("cluster_lock_hash", meta.ClusterLockHash),
			)
		}

		if meta.ClusterLockHash != "" && clusterLockHash != meta.ClusterLockHash {
			elapsedPeriod := time.Since(meta.Timestamp)
			if elapsedPeriod < gracePeriod {
				waitTime := gracePeriod - elapsedPeriod
				errText := fmt.Sprintf("an existing private key lock file is present with a different cluster lock hash, for safety reasons, you must wait for %v before starting charon with a modified cluster", waitTime)

				return Service{}, errors.New(
					errText,
					z.Str("path", privKeyFilePath),
					z.Str("command", meta.Command),
					z.Str("existing_cluster_lock_hash", meta.ClusterLockHash),
					z.Str("current_cluster_lock_hash", clusterLockHash),
					z.Str("grace_period", gracePeriod.String()),
				)
			}
		}
	}

	if err := writeFile(privKeyFilePath, clusterLockHash, command, time.Now()); err != nil {
		return Service{}, err
	}

	return Service{
		clusterLockHash: clusterLockHash,
		command:         command,
		path:            privKeyFilePath,
		updatePeriod:    updatePeriod,
		quit:            make(chan struct{}),
		done:            make(chan struct{}),
	}, nil
}

// Service is a private key locking service.
type Service struct {
	clusterLockHash string
	command         string
	path            string
	updatePeriod    time.Duration
	quit            chan struct{} // Quit exits the Run goroutine if closed.
	done            chan struct{} // Done is closed when Run exits, which exits the Close goroutine.
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
				return errors.Wrap(err, "delete private key lock file")
			}

			return nil
		case <-tick.C:
			// Overwrite lockfile with new metadata
			if err := writeFile(s.path, s.clusterLockHash, s.command, time.Now()); err != nil {
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
	Command         string    `json:"command"`
	Timestamp       time.Time `json:"timestamp"`
	ClusterLockHash string    `json:"cluster_lock_hash,omitempty"`
}

// writeFile creates or updates the file with the latest metadata.
func writeFile(path, clusterLockHash, command string, now time.Time) error {
	b, err := json.Marshal(metadata{Command: command, Timestamp: now, ClusterLockHash: clusterLockHash})
	if err != nil {
		return errors.Wrap(err, "marshal private key lock file")
	}

	//nolint:gosec // Readable and writable for all users is fine for this file.
	if err := os.WriteFile(path, b, 0o666); err != nil {
		return errors.Wrap(err, "write private key lock file", z.Str("path", path))
	}

	return nil
}

type clusterLockHash struct {
	LockHash string `json:"lock_hash"`
}

// readClusterLockHash reads only lock_hash field from the cluster lock file.
// Returns empty string if file doesn't exist (e.g., during DKG before cluster-lock.json is created).
func readClusterLockHash(clusterLockFilePath string) (string, error) {
	content, err := os.ReadFile(clusterLockFilePath)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil // File doesn't exist yet, return empty hash
	} else if err != nil {
		return "", errors.Wrap(err, "read cluster lock file", z.Str("path", clusterLockFilePath))
	}

	var hash clusterLockHash
	if err := json.Unmarshal(content, &hash); err != nil {
		return "", errors.Wrap(err, "decode cluster lock hash file", z.Str("path", clusterLockFilePath))
	}

	return hash.LockHash, nil
}
