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

// LoadManifest loads a cluster manifest from disk by reading either from cluster manifest or legacy lock file.
// If both files are provided, it first reads the manifest file before reading the legacy lock file.
func LoadManifest(manifestFile, legacyLockFile string, lockCallback func(cluster.Lock) error) (*manifestpb.Cluster, error) {
	dag, err := LoadDAG(manifestFile, legacyLockFile, lockCallback)
	if err != nil {
		return nil, errors.Wrap(err, "load dag from disk")
	}

	cluster, err := Materialise(dag)
	if err != nil {
		return nil, errors.Wrap(err, "materialise dag")
	}

	return cluster, nil
}

// LoadDAG loads a raw DAG from disk by reading either from cluster manifest or legacy lock file.
// If both files are provided, it first reads the manifest file before reading the legacy lock file.
func LoadDAG(manifestFile, legacyLockFile string, lockCallback func(cluster.Lock) error) (*manifestpb.SignedMutationList, error) {
	b, err := os.ReadFile(manifestFile)
	if err == nil {
		rawDAG := new(manifestpb.SignedMutationList)
		if err := proto.Unmarshal(b, rawDAG); err != nil {
			return rawDAG, errors.Wrap(err, "unmarshal cluster manifest")
		}

		return rawDAG, nil
	}

	rawDAG, err := loadLegacyLock(legacyLockFile, lockCallback)
	if err != nil {
		return nil, errors.Wrap(err, "load legacy lock")
	}

	return rawDAG, nil
}

func loadLegacyLock(filename string, lockCallback func(cluster.Lock) error) (*manifestpb.SignedMutationList, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrap(err, "read legacy lock file")
	}

	var lock cluster.Lock

	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, errors.Wrap(err, "unmarshal legacy lock")
	}

	if lockCallback != nil {
		if err := lockCallback(lock); err != nil {
			return nil, err
		}
	}

	legacy, err := NewRawLegacyLock(b)
	if err != nil {
		return nil, errors.Wrap(err, "create legacy lock")
	}

	return &manifestpb.SignedMutationList{Mutations: []*manifestpb.SignedMutation{legacy}}, nil
}
