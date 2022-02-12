// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package app

import (
	"encoding/json"
	"os"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/types"
)

// loadManifest reads the cluster manifest from the given file path.
func loadManifest(file string) (types.Manifest, error) {
	buf, err := os.ReadFile(file)
	if err != nil {
		return types.Manifest{}, err
	}

	var res types.Manifest
	err = json.Unmarshal(buf, &res)
	if err != nil {
		return types.Manifest{}, errors.Wrap(err, "unmarshal manifest")
	}

	return res, nil
}
