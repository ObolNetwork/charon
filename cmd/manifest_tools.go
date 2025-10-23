// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
)

// loadClusterLock loads cluster lock from disk.
func loadClusterLock(lockFilePath string) (*manifestpb.Cluster, error) {
	verifyLock := func(lock cluster.Lock) error {
		if err := lock.VerifyHashes(); err != nil {
			return errors.Wrap(err, "verify cluster lock hashes")
		}

		if err := lock.VerifySignatures(nil); err != nil {
			return errors.Wrap(err, "verify cluster lock signatures")
		}

		return nil
	}

	cluster, err := manifest.LoadCluster("", lockFilePath, verifyLock)
	if err != nil {
		return nil, errors.Wrap(err, "load cluster lock", z.Str("path", lockFilePath))
	}

	return cluster, nil
}
