// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"fmt"
	"os"
	"path"

	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
)

// nolint(unparam) // holding this until the TODO item is merged
// loadClusterManifest returns the cluster manifest from the provided config. It returns true if
// the cluster was loaded from a legacy lock file.
// TODO(xenowits): Refactor to remove boolean in return values, ie, return only (cluster, error).
func loadClusterManifest(manifestFile, lockFile string) (*manifestpb.Cluster, bool, error) {
	verifyLock := func(lock cluster.Lock) error {
		if err := lock.VerifyHashes(); err != nil {
			return errors.Wrap(err, "cluster lock hash verification failed")
		}

		if err := lock.VerifySignatures(); err != nil {
			return errors.Wrap(err, "cluster lock signature verification failed")
		}

		return nil
	}

	cluster, isLegacyLock, err := manifest.Load(manifestFile, lockFile, verifyLock)
	if err != nil {
		return nil, false, errors.Wrap(err, "load cluster manifest")
	}

	return cluster, isLegacyLock, nil
}

// writeClusterManifests writes the provided cluster manifest to node directories on disk.
func writeClusterManifests(clusterDir string, numOps int, cluster *manifestpb.Cluster) error {
	b, err := proto.Marshal(cluster)
	if err != nil {
		return errors.Wrap(err, "marshal proto")
	}

	// Write cluster manifest to node directories on disk
	for i := 0; i < numOps; i++ {
		dir := path.Join(clusterDir, fmt.Sprintf("node%d", i))
		filename := path.Join(dir, "cluster-manifest.pb")
		//nolint:gosec // File needs to be read-write since the cluster manifest is modified by mutations.
		err = os.WriteFile(filename, b, 0o644) // Read-write
		if err != nil {
			return errors.Wrap(err, "write cluster manifest")
		}
	}

	return nil
}
