// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	"encoding/json"
	"os"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
)

// Load loads a cluster state from disk. It supports both legacy lock files and raw DAG files.
func Load(file string) (Cluster, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return Cluster{}, errors.Wrap(err, "read file")
	}

	var rawDAG RawDAG
	if err := json.Unmarshal(b, &rawDAG); err != nil {
		return loadLegacyLock(b)
	}

	return Materialise(rawDAG)
}

func loadLegacyLock(input []byte) (Cluster, error) {
	var lock cluster.Lock
	if err := json.Unmarshal(input, &lock); err != nil {
		return Cluster{}, errors.Wrap(err, "unmarshal legacy lock")
	}

	// TODO(corver): Verify the lock with support for no-verify.

	legacy, err := NewLegacyLock(lock)
	if err != nil {
		return Cluster{}, errors.Wrap(err, "create legacy lock")
	}

	return legacy.Transform(Cluster{})
}
