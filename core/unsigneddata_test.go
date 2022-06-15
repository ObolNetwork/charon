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

package core_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

func TestCloneVersionedBeaconBlock(t *testing.T) {
	block := testutil.RandomCoreVersionBeaconBlock(t)
	slot1, err := block.Slot()
	require.NoError(t, err)

	clone, err := block.Clone()
	require.NoError(t, err)
	block2 := clone.(core.VersionedBeaconBlock)
	slot2, err := block2.Slot()
	require.NoError(t, err)

	require.Equal(t, slot1, slot2)
}
