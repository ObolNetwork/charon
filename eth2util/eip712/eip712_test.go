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

package eip712_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/eip712"
)

func TestCreatorHash(t *testing.T) {
	// Obtained from legacy unit tests.
	data := eip712.TypedData{
		Domain: eip712.Domain{
			Name:    "Obol",
			Version: "1",
			ChainID: uint64(eth2util.Sepolia.ChainID),
		},
		Type: eip712.Type{
			Name: "CreatorConfigHash",
			Fields: []eip712.Field{
				{
					Name:  "creator_config_hash",
					Type:  "string",
					Value: "0xe57f66637bdfa05cce6a78e8cf4120d67d305b485367a69baa5f738436533bcb",
				},
			},
		},
	}

	resp, err := eip712.HashTypedData(data)
	require.NoError(t, err)
	require.Equal(t, "7c8fe012e2f872ca7ec870164184f57b921166f80565ff74af7bee5796f973e4", fmt.Sprintf("%x", resp))
}
