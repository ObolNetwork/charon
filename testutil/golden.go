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

// Package testutil provides test utilities.
package testutil

import (
	"encoding/json"
	"flag"
	"os"
	"path"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	update = flag.Bool("update", false, "Create or update golden files, instead of comparing them")
	clean  = flag.Bool("clean", false, "Deletes the testdata folder before updating (noop of update==false)")
)

var cleanOnce sync.Once

// RequireGoldenBytes asserts that a golden testdata file exists containing the exact data.
// This is heavily inspired from https://github.com/sebdah/goldie.
func RequireGoldenBytes(t *testing.T, data []byte) {
	t.Helper()

	filename := path.Join("testdata", strings.ReplaceAll(t.Name(), "/", "_")+".golden")

	if *update {
		if *clean {
			cleanOnce.Do(func() {
				_ = os.RemoveAll("testdata")
			})
		}

		require.NoError(t, os.MkdirAll("testdata", 0o755))

		_ = os.Remove(filename)
		require.NoError(t, os.WriteFile(filename, data, 0o644)) //nolint:gosec

		return
	}

	expected, err := os.ReadFile(filename)
	if os.IsNotExist(err) {
		t.Fatalf("golden file does not exist, %s, generate by running with -update", filename)
		return
	}

	require.Equalf(t, string(expected), string(data), "Golden file mismatch, %s", filename)
}

// RequireGoldenJSON asserts that a golden testdata file exists containing the JSON serialised form of the data object.
// This is heavily inspired from https://github.com/sebdah/goldie.
func RequireGoldenJSON(t *testing.T, data interface{}) {
	t.Helper()

	b, err := json.MarshalIndent(data, "", " ")
	require.NoError(t, err)

	RequireGoldenBytes(t, b)
}
