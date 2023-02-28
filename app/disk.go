// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"encoding/json"
	"os"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
)

// loadLock reads the cluster lock from the given file path.
func loadLock(ctx context.Context, conf Config) (cluster.Lock, error) {
	if conf.TestConfig.Lock != nil {
		return *conf.TestConfig.Lock, nil
	}

	buf, err := os.ReadFile(conf.LockFile)
	if err != nil {
		return cluster.Lock{}, errors.Wrap(err, "read lock")
	}

	var lock cluster.Lock
	err = json.Unmarshal(buf, &lock)
	if err != nil {
		return cluster.Lock{}, errors.Wrap(err, "unmarshal lock")
	}

	if err := lock.VerifyHashes(); err != nil && !conf.NoVerify {
		return cluster.Lock{}, errors.Wrap(err, "cluster lock hash verification failed. Run with --no-verify to bypass verification at own risk")
	} else if err != nil && conf.NoVerify {
		log.Warn(ctx, "Ignoring failed cluster lock hash verification due to --no-verify flag", err)
	}

	if err := lock.VerifySignatures(); err != nil && !conf.NoVerify {
		return cluster.Lock{}, errors.Wrap(err, "cluster lock signature verification failed. Run with --no-verify to bypass verification at own risk")
	} else if err != nil && conf.NoVerify {
		log.Warn(ctx, "Ignoring failed cluster lock signature verification due to --no-verify flag", err)
	}

	return lock, nil
}
