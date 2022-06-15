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

package featureset_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/featureset"
)

// setup initialises global variable per test.
func setup(t *testing.T) {
	t.Helper()

	err := featureset.Init(context.Background(), featureset.DefaultConfig())
	require.NoError(t, err)
}

func TestConfig(t *testing.T) {
	setup(t)

	err := featureset.Init(context.Background(), featureset.DefaultConfig())
	require.NoError(t, err)

	err = featureset.Init(context.Background(), featureset.Config{
		MinStatus: "alpha",
		Enabled:   []string{"ignored"},
	})
	require.NoError(t, err)

	require.True(t, featureset.Enabled(featureset.QBFTConsensus))
}

func TestEnableForT(t *testing.T) {
	setup(t)

	testFeature := featureset.Feature("test")
	require.False(t, featureset.Enabled(testFeature))

	featureset.EnableForT(t, testFeature)
	require.True(t, featureset.Enabled(testFeature))

	featureset.DisableForT(t, testFeature)
	require.False(t, featureset.Enabled(testFeature))
}

func TestQBFT(t *testing.T) {
	setup(t)

	require.True(t, featureset.Enabled(featureset.QBFTConsensus))
}
