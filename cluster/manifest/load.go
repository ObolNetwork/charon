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

// Load loads a cluster from disk by reading both the cluster manifest and legacy lock files.
// If both files are loaded successfully and the cluster hashes from the manifest and legacy lock files match,
// the cluster read from the manifest file is returned. Otherwise, an error is returned indicating a mismatch
// between the cluster hashes. If loading from the manifest file succeeds, the cluster read from the manifest file
// is returned. Otherwise, the cluster read from the legacy lock file is returned.
func Load(manifestFile, legacyLockFile string, lockCallback func(cluster.Lock) error) (*manifestpb.Cluster, error) {
	manifestCluster, err1 := loadClusterManifest(manifestFile)
	legacyCluster, err2 := loadLegacyLock(legacyLockFile, lockCallback)

	switch {
	case err1 == nil && err2 == nil:
		// Both files loaded successfully, check if cluster hashes match
		if !bytes.Equal(manifestCluster.InitialMutationHash, legacyCluster.InitialMutationHash) {
			return nil, errors.New("manifest and legacy cluster hashes don't match",
				z.Str("manifest_hash", hex.EncodeToString(manifestCluster.InitialMutationHash)),
				z.Str("legacy_hash", hex.EncodeToString(legacyCluster.InitialMutationHash)))
		}

		return manifestCluster, nil
	case err1 == nil:
		// Cluster manifest loaded successfully
		return manifestCluster, nil
	case err2 == nil:
		// Legacy cluster lock loaded successfully
		return legacyCluster, nil
	default:
		// None of the files were loaded successfully, so return an error
		return nil, errors.New("couldn't load cluster either from manifest or legacy lock file", z.Err(err1), z.Err(err2))
	}
}

// loadClusterManifest loads a cluster from disk using the provided manifest file.
func loadClusterManifest(manifestFile string) (*manifestpb.Cluster, error) {
	b, err := os.ReadFile(manifestFile)
	if err != nil {
		return nil, errors.Wrap(err, "read manifest file")
	}

	manifest := new(manifestpb.Cluster)
	if err = proto.Unmarshal(b, manifest); err != nil {
		return nil, errors.Wrap(err, "unmarshal cluster manifest")
	}

	return manifest, nil
}

// loadLegacyLock loads a cluster from disk using the provided legacy lock file.
func loadLegacyLock(legacyLockFile string, lockCallback func(cluster.Lock) error) (*manifestpb.Cluster, error) {
	b, err := os.ReadFile(legacyLockFile)
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

	legacy, err := NewLegacyLock(lock)
	if err != nil {
		return nil, errors.Wrap(err, "create legacy lock")
	}

	return Materialise(&manifestpb.SignedMutationList{Mutations: []*manifestpb.SignedMutation{legacy}})
}
