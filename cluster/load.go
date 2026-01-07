// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	"context"
	"encoding/json"
	"os"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth1wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// LoadClusterLockAndVerify loads and verifies the cluster lock. Suitable for cmd tools.
func LoadClusterLockAndVerify(ctx context.Context, lockFilePath string) (*Lock, error) {
	eth1Cl := eth1wrap.NewDefaultEthClientRunner("")
	go eth1Cl.Run(ctx)

	return LoadClusterLock(ctx, lockFilePath, false, eth1Cl)
}

// LoadClusterLock loads and verifies the cluster lock.
func LoadClusterLock(ctx context.Context, lockFilePath string, noVerify bool, eth1Cl eth1wrap.EthClientRunner) (*Lock, error) {
	b, err := os.ReadFile(lockFilePath)
	if err != nil {
		return nil, errors.Wrap(err, "read cluster-lock.json", z.Str("path", lockFilePath))
	}

	var lock Lock
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, errors.Wrap(err, "unmarshal cluster-lock.json", z.Str("path", lockFilePath))
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := lock.VerifyHashes(); err != nil && !noVerify {
		return nil, errors.Wrap(err, "verify cluster lock hashes (run with --no-verify to bypass verification at own risk)")
	} else if err != nil && noVerify {
		log.Warn(ctx, "Ignoring failed cluster lock hashes verification due to --no-verify flag", err)
	}

	if err := lock.VerifySignatures(eth1Cl); err != nil && !noVerify {
		return nil, errors.Wrap(err, "verify cluster lock signatures (run with --no-verify to bypass verification at own risk)")
	} else if err != nil && noVerify {
		log.Warn(ctx, "Ignoring failed cluster lock signature verification due to --no-verify flag", err)
	}

	return &lock, nil
}
