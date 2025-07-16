// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
)

// loadClusterManifest loads cluster manifest from disk.
func loadClusterManifest(manifestFilePath, lockFilePath string) (*manifestpb.Cluster, error) {
	verifyLock := func(lock cluster.Lock) error {
		if err := lock.VerifyHashes(); err != nil {
			return errors.Wrap(err, "cluster lock hash verification failed")
		}

		if err := lock.VerifySignatures(nil); err != nil {
			return errors.Wrap(err, "cluster lock signature verification failed")
		}

		return nil
	}

	cluster, err := manifest.LoadCluster(manifestFilePath, lockFilePath, verifyLock)
	if err != nil {
		return nil, errors.Wrap(err, "load cluster manifest from disk")
	}

	return cluster, nil
}
