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

package dkg

import (
	"encoding/json"
	"os"
	"path"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil/keystore"
)

// loadManifest loads and returns the manifest from the file on disk.
func loadManifest(filename string) (app.Manifest, error) {
	buf, err := os.ReadFile(filename)
	if err != nil {
		return app.Manifest{}, errors.Wrap(err, "read manifest")
	}

	var res app.Manifest
	err = json.Unmarshal(buf, &res)
	if err != nil {
		return app.Manifest{}, errors.Wrap(err, "unmarshal manifest")
	}

	return res, nil
}

// writeOutput writes the updated manifest lock file and private share keystores to disk.
func writeOutput(manifest app.Manifest, datadir string, outs []output) error {
	clone := manifest
	var secrets []*bls_sig.SecretKey
	for _, out := range outs {
		tss, err := tbls.NewTSS(out.Verifier, len(manifest.Peers))
		if err != nil {
			return err
		}

		clone.DVs = append(clone.DVs, tss)

		secrets = append(secrets, out.Share)
	}

	err := keystore.StoreKeys(secrets, datadir)
	if err != nil {
		return err
	}

	b, err := json.Marshal(clone)
	if err != nil {
		return errors.Wrap(err, "marshal manifest")
	}

	err = os.WriteFile(path.Join(datadir, "manifest.lock"), b, 0o600)
	if err != nil {
		return errors.Wrap(err, "write manifest lock")
	}

	return nil
}
