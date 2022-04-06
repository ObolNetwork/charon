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
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadManifest(t *testing.T) {
	manifest, _, _ := NewClusterForT(t, 1, 2, 3, 0)

	b, err := json.MarshalIndent(manifest, "", " ")
	require.NoError(t, err)

	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	filename := path.Join(dir, "manifest.json")

	err = os.WriteFile(filename, b, 0o644)
	require.NoError(t, err)

	conf := Config{ManifestFile: filename}
	actual, err := loadManifest(conf)
	require.NoError(t, err)

	b2, err := json.Marshal(actual)
	require.NoError(t, err)
	require.JSONEq(t, string(b), string(b2))
}
