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

package main

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIntegration tests merge pr action if a GITHUB_TOKEN env var is found.
func TestIntegration(t *testing.T) {
	if _, ok := os.LookupEnv("GITHUB_TOKEN"); !ok {
		return
	}

	b, err := os.ReadFile("testdata/pr.json")
	require.NoError(t, err)
	require.NoError(t, os.Setenv("GITHUB_PR", string(b)))

	err = run(context.Background())
	require.NoError(t, err)
}
