// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

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
