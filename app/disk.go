// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/state"
)

// loadClusterState returns the cluster state from the given file path.
func loadClusterState(ctx context.Context, conf Config) (state.Cluster, error) {
	if conf.TestConfig.Lock != nil {
		return state.NewClusterFromLock(*conf.TestConfig.Lock)
	}

	verifyLock := func(lock cluster.Lock) error {
		if err := lock.VerifyHashes(); err != nil && !conf.NoVerify {
			return errors.Wrap(err, "cluster lock hash verification failed. Run with --no-verify to bypass verification at own risk")
		} else if err != nil && conf.NoVerify {
			log.Warn(ctx, "Ignoring failed cluster lock hash verification due to --no-verify flag", err)
		}

		if err := lock.VerifySignatures(); err != nil && !conf.NoVerify {
			return errors.Wrap(err, "cluster lock signature verification failed. Run with --no-verify to bypass verification at own risk")
		} else if err != nil && conf.NoVerify {
			log.Warn(ctx, "Ignoring failed cluster lock signature verification due to --no-verify flag", err)
		}

		return nil
	}

	clusterState, err := state.Load(conf.LockFile, verifyLock)
	if err != nil {
		return state.Cluster{}, errors.Wrap(err, "load cluster state")
	}

	return clusterState, nil
}
