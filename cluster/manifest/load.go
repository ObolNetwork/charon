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

// LoadMetadata represents the result of loading a cluster from cluster manifest or legacy lock file.
type LoadMetadata struct {
	Filename     string // Name of the file from which the cluster was loaded
	IsLegacyLock bool   // True if cluster was loaded from legacy lock file
}

// Load loads a cluster from disk. It supports reading from both cluster manifest and legacy lock files.
// If both files are provided, it first reads the manifest file before reading the legacy lock file.
// TODO(xenowits): Remove loading from legacy lock when we fully adopt mutable cluster manifests.
func Load(manifestFile, legacyLockFile string, lockCallback func(cluster.Lock) error) (*manifestpb.Cluster, LoadMetadata, error) {
	b, err := os.ReadFile(manifestFile)
	if err == nil {
		manifest := new(manifestpb.Cluster)
		if err := proto.Unmarshal(b, manifest); err != nil {
			return nil, LoadMetadata{}, errors.Wrap(err, "unmarshal cluster manifest")
		}

		return manifest, LoadMetadata{Filename: manifestFile, IsLegacyLock: false}, nil
	}

	b, err = os.ReadFile(legacyLockFile)
	if err != nil {
		return nil, LoadMetadata{}, errors.Wrap(err, "read legacy lock file")
	}

	rawDAG := new(manifestpb.SignedMutationList)
	if err := proto.Unmarshal(b, rawDAG); err != nil {
		m, err := loadLegacyLock(b, lockCallback)
		if err != nil {
			return nil, LoadMetadata{}, errors.Wrap(err, "load legacy lock")
		}

		return m, LoadMetadata{Filename: legacyLockFile, IsLegacyLock: true}, nil
	}

	m, err := Materialise(rawDAG)
	if err != nil {
		return nil, LoadMetadata{}, errors.Wrap(err, "materialise raw DAG")
	}

	return m, LoadMetadata{Filename: legacyLockFile, IsLegacyLock: true}, nil
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
