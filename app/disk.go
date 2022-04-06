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
	"encoding/json"
	"os"

	"github.com/obolnetwork/charon/app/errors"
)

// loadManifest reads the cluster manifest from the given file path.
func loadManifest(conf Config) (Manifest, error) {
	if conf.TestConfig.Manifest != nil {
		return *conf.TestConfig.Manifest, nil
	}

	buf, err := os.ReadFile(conf.ManifestFile)
	if err != nil {
		return Manifest{}, errors.Wrap(err, "read manifest")
	}

	var res Manifest
	err = json.Unmarshal(buf, &res)
	if err != nil {
		return Manifest{}, errors.Wrap(err, "unmarshal manifest")
	}

	return res, nil
}
