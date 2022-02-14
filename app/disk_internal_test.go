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

	"github.com/obolnetwork/charon/types"
)

func TestLoadManifest(t *testing.T) {
	manifest, _, _ := types.NewClusterForT(t, 1, 2, 3, 0)

	b, err := json.MarshalIndent(manifest, "", " ")

	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	filename := path.Join(dir, "manifest.json")

	err = os.WriteFile(filename, b, 0o644)
	require.NoError(t, err)

	actual, err := loadManifest(filename)
	require.NoError(t, err)

	b2, err := json.Marshal(actual)
	require.NoError(t, err)
	require.JSONEq(t, string(b), string(b2))
}
