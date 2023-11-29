// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package manifest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"

	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
)

// LoadCluster returns the current cluster state from disk by reading either from cluster manifest or legacy lock file.
// If both files are provided, both files are read and
//   - If cluster hashes don't match, an error is returned
//   - If cluster hashes match, the cluster loaded from the manifest file is returned
//
// It returns an error if the cluster can't be loaded from either file.
func LoadCluster(manifestFile, legacyLockFile string, lockCallback func(cluster.Lock) error) (*manifestpb.Cluster, error) {
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

// LoadDAG returns the raw cluster DAG from disk by reading either from cluster manifest or legacy lock file.
// If both files are provided, both files are read and
//   - If cluster hashes don't match, an error is returned
//   - If cluster hashes match, the DAG loaded from the manifest file is returned
//
// It returns an error if the DAG can't be loaded from either file.
func LoadDAG(manifestFile, legacyLockFile string, lockCallback func(cluster.Lock) error) (*manifestpb.SignedMutationList, error) {
	dagManifest, errManifest := loadDAGFromManifest(manifestFile)
	dagLegacy, errLegacy := loadDAGFromLegacyLock(legacyLockFile, lockCallback)

	switch {
	case errManifest == nil && errLegacy == nil:
		// Both files loaded successfully, check if cluster hashes match
		if err := clusterHashesMatch(dagManifest, dagLegacy); err != nil {
			return nil, err
		}

		return dagManifest, nil
	case errManifest == nil:
		// Cluster manifest loaded successfully
		return dagManifest, nil
	case errLegacy == nil:
		// Legacy cluster lock loaded successfully
		return dagLegacy, nil
	case errors.Is(errLegacy, os.ErrNotExist) && errors.Is(errManifest, os.ErrNotExist):
		return nil, errors.New("no file found", z.Str("lock-file", legacyLockFile), z.Str("manifest-file", manifestFile))
	case !errors.Is(errLegacy, os.ErrNotExist):
		// Return legacy lock error as it exists but failed to load.
		return nil, errors.Wrap(errLegacy, "couldn't load cluster from legacy lock file")
	default:
		return nil, errors.Wrap(errManifest, "couldn't load cluster from manifest file")
	}
}

// loadDAGFromManifest returns the raw DAG from cluster manifest file on disk.
func loadDAGFromManifest(filename string) (*manifestpb.SignedMutationList, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrap(err, "read manifest file", z.Str("file", filename))
	}

	rawDAG := new(manifestpb.SignedMutationList)
	if err := proto.Unmarshal(b, rawDAG); err != nil {
		return rawDAG, errors.Wrap(err, "unmarshal cluster dag", z.Str("file", filename))
	}

	return rawDAG, nil
}

// loadDAGFromLegacyLock returns the raw DAG from legacy lock file on disk.
// It also accepts a callback that is called on the loaded lock.
func loadDAGFromLegacyLock(filename string, lockCallback func(cluster.Lock) error) (*manifestpb.SignedMutationList, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrap(err, "read legacy lock file", z.Str("file", filename))
	}

	var lock cluster.Lock

	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, errors.Wrap(err, "unmarshal legacy lock", z.Str("file", filename))
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

// clusterHashesMatch returns an error if the cluster hashes of the provided DAGs don't match.
func clusterHashesMatch(dagManifest, dagLegacy *manifestpb.SignedMutationList) error {
	hashManifest, err := Hash(dagManifest.Mutations[0])
	if err != nil {
		return errors.Wrap(err, "materialise dag")
	}

	hashLegacy, err := Hash(dagLegacy.Mutations[0])
	if err != nil {
		return errors.Wrap(err, "materialise dag")
	}

	if !bytes.Equal(hashManifest, hashLegacy) {
		return errors.New("manifest and legacy cluster hashes don't match",
			z.Str("manifest_hash", hex.EncodeToString(hashManifest)),
			z.Str("legacy_hash", hex.EncodeToString(hashLegacy)))
	}

	return nil
}
