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

package app_test

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app"
)

//go:generate go test -tags=generic -run=TestManifestJSON -update
var update = flag.Bool("update", false, "update the manifest json golden test files")

func TestManifestJSON(t *testing.T) {
	if *update {
		require.NoError(t, os.RemoveAll("testdata/"))
		require.NoError(t, os.Mkdir("testdata", 0o755))
	}

	for i := 0; i < 3; i++ {
		manifest, _, _ := app.NewClusterForT(t, i+1, 2+i, 3+(2*i), i+1)

		// Marshal to JSON.
		data, err := json.MarshalIndent(manifest, "", "  ")
		require.NoError(t, err)

		filename := fmt.Sprintf("testdata/manifest%d.json", i)

		if *update {
			// nolint:gosec
			err := os.WriteFile(filename, data, 0o644)
			require.NoError(t, err)

			continue
		}

		actual, err := os.ReadFile(filename)
		require.NoError(t, err)
		require.JSONEq(t, string(data), string(actual))

		// Unmarshal from JSON.
		var manifest2 app.Manifest
		err = json.Unmarshal(actual, &manifest2)
		require.NoError(t, err)

		// TODO(corver): Figure out how a better way to compare manifest structs.
		require.Equal(t, manifest.Peers, manifest2.Peers)
		require.Equal(t, len(manifest.DVs), len(manifest2.DVs))
		for i := 0; i < len(manifest.DVs); i++ {
			tss1 := manifest.DVs[i]
			tss2 := manifest2.DVs[i]
			require.Equal(t, tss1.NumShares(), tss2.NumShares())
			require.Equal(t, tss1.Verifier(), tss2.Verifier())
			require.Equal(t, tss1.PublicKey(), tss2.PublicKey())
		}
	}
}
