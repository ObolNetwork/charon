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

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

func TestSetBlockSig(t *testing.T) {
	block := core.VersionedSignedBeaconBlock{
		VersionedSignedBeaconBlock: spec.VersionedSignedBeaconBlock{
			Version: spec.DataVersionBellatrix,
			Bellatrix: &bellatrix.SignedBeaconBlock{
				Message:   testutil.RandomBellatrixBeaconBlock(t),
				Signature: testutil.RandomEth2Signature(),
			},
		},
	}

	clone, err := block.SetSignature(testutil.RandomCoreSignature())
	require.NoError(t, err)
	require.NotEqual(t, clone.Signature(), block.Signature())
}

func TestSetBlindedBlockSig(t *testing.T) {
	block := core.VersionedSignedBlindedBeaconBlock{
		VersionedSignedBlindedBeaconBlock: eth2api.VersionedSignedBlindedBeaconBlock{
			Version: spec.DataVersionBellatrix,
			Bellatrix: &eth2v1.SignedBlindedBeaconBlock{
				Message:   testutil.RandomBellatrixBlindedBeaconBlock(t),
				Signature: testutil.RandomEth2Signature(),
			},
		},
	}

	clone, err := block.SetSignature(testutil.RandomCoreSignature())
	require.NoError(t, err)
	require.NotEqual(t, clone.Signature(), block.Signature())
}
