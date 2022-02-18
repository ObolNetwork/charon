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

package types_test

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/types"
)

//go:generate go test -tags=generic -run=TestManifestJSON -update
var update = flag.Bool("update", false, "update the manifest json golden test files")

func TestManifestJSON(t *testing.T) {
	if *update {
		require.NoError(t, os.RemoveAll("testdata/"))
		require.NoError(t, os.Mkdir("testdata", 0o755))
	}

	for i := 0; i < 3; i++ {
		manifest, _, _ := types.NewClusterForT(t, i+1, 2+i, 3+(2*i), i+1)

		// Marshal to JSON.
		data, err := json.MarshalIndent(manifest, "", "  ")
		require.NoError(t, err)

		filename := fmt.Sprintf("testdata/manifest%d.json", i)

		if *update {
			err := os.WriteFile(filename, data, 0o644)
			require.NoError(t, err)
			continue
		}

		actual, err := os.ReadFile(filename)
		require.JSONEq(t, string(data), string(actual))

		// Unmarshal from JSON.
		var manifest2 types.Manifest
		err = json.Unmarshal(data, &manifest2)
		require.NoError(t, err)

		// TODO(corver): Figure out how a better way to compare manifest structs.
		require.Equal(t, manifest.Peers, manifest2.Peers)
		require.Equal(t, len(manifest.DVs), len(manifest2.DVs))
		for i := 0; i < len(manifest.DVs); i++ {
			tss1 := manifest.DVs[i]
			tss2 := manifest2.DVs[i]
			require.Equal(t, tss1.NumShares, tss2.NumShares)
			require.Equal(t, tss1.Verifier, tss2.Verifier)
		}
	}
}

func TestDecodeENR(t *testing.T) {
	manifest, _, _ := types.NewClusterForT(t, 1, 3, 4, 0)

	for _, p := range manifest.Peers {
		enrStr, err := types.EncodeENR(p.ENR)
		require.NoError(t, err)

		record2, err := types.DecodeENR(enrStr)
		require.NoError(t, err)
		require.Equal(t, p.ENR, record2)
	}
}

func TestDecodeENR_InvalidBase64(t *testing.T) {
	_, err := types.DecodeENR("enr:###")
	require.Error(t, err)
	require.Contains(t, err.Error(), "illegal base64 data at input byte 0")
}

func TestDecodeENR_InvalidRLP(t *testing.T) {
	_, err := types.DecodeENR("enr:AAAAAAAA")
	require.Error(t, err)
	require.Contains(t, err.Error(), "rlp: expected List")
}

func TestDecodeENR_Oversize(t *testing.T) {
	_, err := types.DecodeENR("enr:-IS4QBnEa-Oftjk7-sGRAY7IrvL5YjATdcHbqR5l2aXX2M25CiawfwaXh0k9hm98dCfdnqhz9mE-BfemFdjuL9KtHqgBgmlkgnY0gmlwhB72zxGJc2VjcDI1NmsxoQMaK8SspTrUgB8IYVI3qDgFYsHymPVsWlvIW477kxaKUIN0Y3CCJpUAAAA=")
	require.Error(t, err)
	require.Contains(t, err.Error(), "input contains more than one value")
}
