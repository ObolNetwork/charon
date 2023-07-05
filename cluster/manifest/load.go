// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package manifest

import (
	"encoding/json"
	"os"

	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
)

// Load loads a cluster from disk and returns true if cluster was loaded from a legacy lock file.
// It supports reading from both cluster manifest and legacy lock files.
// If both files are provided, it first reads the manifest file before reading the legacy lock file.
// TODO(xenowits): Refactor to return only (cluster, error).
func Load(manifestFile, legacyLockFile string, lockCallback func(cluster.Lock) error) (*manifestpb.Cluster, bool, error) {
	b, err := os.ReadFile(manifestFile)
	if err == nil {
		manifest := new(manifestpb.Cluster)
		if err := proto.Unmarshal(b, manifest); err != nil {
			return nil, false, errors.Wrap(err, "unmarshal cluster manifest")
		}

		return manifest, false, nil
	}

	b, err = os.ReadFile(legacyLockFile)
	if err != nil {
		return nil, false, errors.Wrap(err, "read legacy lock file")
	}

	m, err := loadLegacyLock(b, lockCallback)
	if err != nil {
		return nil, false, errors.Wrap(err, "load legacy lock")
	}

	return m, true, nil
}

func loadLegacyLock(input []byte, lockCallback func(cluster.Lock) error) (*manifestpb.Cluster, error) {
	var lock cluster.Lock

	if err := json.Unmarshal(input, &lock); err != nil {
		return nil, errors.Wrap(err, "unmarshal legacy lock")
	}

	if lockCallback != nil {
		if err := lockCallback(lock); err != nil {
			return nil, err
		}
	}

	legacy, err := NewLegacyLock(lock)
	if err != nil {
		return nil, errors.Wrap(err, "create legacy lock")
	}

	return Materialise(&manifestpb.SignedMutationList{Mutations: []*manifestpb.SignedMutation{legacy}})
}
