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

package consensus

import (
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -update -clean

func TestHashProto(t *testing.T) {
	rand.Seed(0)

	duty := testutil.RandomAttestationDuty(t)
	data := testutil.RandomAttestationData()
	unsigned, err := core.EncodeAttesterUnsignedData(&core.AttestationData{
		Data: *data,
		Duty: *duty,
	})
	require.NoError(t, err)

	set := core.UnsignedDataSet{
		testutil.RandomCorePubKey(t): unsigned,
	}

	testutil.RequireGoldenJSON(t, set)

	setPB := core.UnsignedDataSetToProto(set)
	hash, err := hashProto(setPB)
	require.NoError(t, err)

	require.Equal(t,
		"2629f0aaf0f78c37ad7aeae4cc3ee0ff05741a9b341e0002c03b257d62b2e237",
		hex.EncodeToString(hash[:]),
	)
}
