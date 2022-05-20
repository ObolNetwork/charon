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

package compose

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/goccy/go-yaml"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
)

// Define defines a compose cluster; including both keygen and running definitions.
func Define(ctx context.Context, dir string, clean bool, seed int) error {
	ctx = log.WithTopic(ctx, "define")

	if clean {
		files, err := filepath.Glob(path.Join(dir, "*"))
		if err != nil {
			return errors.Wrap(err, "glob dir")
		}
		log.Info(ctx, "Cleaning compose dir", z.Int("files", len(files)))
		for _, file := range files {
			if err := os.RemoveAll(file); err != nil {
				return errors.Wrap(err, "remove file")
			}
		}
	}

	// TODO(corver): Serve a web UI to allow configuration of default values.

	log.Info(ctx, "Using default config")

	lock, p2pkeys, _ := cluster.NewForT(&testing.T{}, defaultNumVals, defaultThreshold, defaultNumNodes, seed)
	conf := newDefaultConfig()
	conf.Def = lock.Definition
	conf.Def.Name = "compose"
	conf.Def.FeeRecipientAddress = ""
	conf.Def.WithdrawalAddress = ""
	for i := 0; i < len(conf.Def.Operators); i++ {
		conf.Def.Operators[i].Address = ""
	}

	for i, key := range p2pkeys {
		// Best effort creation of folder, rather fail when saving p2pkey file next.
		_ = os.MkdirAll(nodeFile(dir, i, ""), 0o755)

		err := crypto.SaveECDSA(nodeFile(dir, i, "p2pkey"), key)
		if err != nil {
			return errors.Wrap(err, "save p2pkey")
		}
	}

	b, err := json.MarshalIndent(conf, "", " ")
	if err != nil {
		return errors.Wrap(err, "marshal config")
	}

	b, err = yaml.JSONToYAML(b)
	if err != nil {
		return errors.Wrap(err, "yaml config")
	}

	err = os.WriteFile(path.Join(dir, composeFile), b, 0o755) //nolint:gosec
	if err != nil {
		return errors.Wrap(err, "write config")
	}

	log.Info(ctx, "Created config.yml and p2pkeys")

	return nil
}

// nodeFile returns the path to a file in a node folder.
func nodeFile(dir string, i int, file string) string {
	return path.Join(dir, fmt.Sprintf("node%d", i), file)
}
