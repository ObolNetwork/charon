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

	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

func TestEncodeAttesterFetchArg(t *testing.T) {
	attDuty1 := testutil.RandomAttestationDuty(t)

	arg1, err := core.EncodeAttesterFetchArg(attDuty1)
	require.NoError(t, err)

	attDuty2, err := core.DecodeAttesterFetchArg(arg1)
	require.NoError(t, err)

	arg2, err := core.EncodeAttesterFetchArg(attDuty2)
	require.NoError(t, err)

	require.Equal(t, attDuty1, attDuty2)
	require.Equal(t, arg1, arg2)
}

func TestEncodeAttesterUnsignedData(t *testing.T) {
	attData1 := &core.AttestationData{
		Data: *testutil.RandomAttestationData(),
		Duty: *testutil.RandomAttestationDuty(t),
	}

	data1, err := core.EncodeAttesterUnsignedData(attData1)
	require.NoError(t, err)

	attData2, err := core.DecodeAttesterUnsignedData(data1)
	require.NoError(t, err)

	data2, err := core.EncodeAttesterUnsignedData(attData2)
	require.NoError(t, err)

	require.Equal(t, attData1, attData2)
	require.Equal(t, data1, data2)
}

func TestEncodeAttesterParSignedData(t *testing.T) {
	att1 := testutil.RandomAttestation()

	data1, err := core.EncodeAttestationParSignedData(att1, 1)
	require.NoError(t, err)

	att2, err := core.DecodeAttestationParSignedData(data1)
	require.NoError(t, err)

	data2, err := core.EncodeAttestationParSignedData(att2, 1)
	require.NoError(t, err)

	require.Equal(t, att1, att2)
	require.Equal(t, data1, data2)
}

func TestEncodeAttesterAggSignedData(t *testing.T) {
	att1 := testutil.RandomAttestation()

	data1, err := core.EncodeAttestationAggSignedData(att1)
	require.NoError(t, err)

	att2, err := core.DecodeAttestationAggSignedData(data1)
	require.NoError(t, err)

	data2, err := core.EncodeAttestationAggSignedData(att2)
	require.NoError(t, err)

	require.Equal(t, att1, att2)
	require.Equal(t, data1, data2)
}

func TestEncodeRandaoParSignedData(t *testing.T) {
	randao1 := testutil.RandomEth2Signature()

	data1 := core.EncodeRandaoParSignedData(randao1, 1)
	randao2 := core.DecodeRandaoParSignedData(data1)
	data2 := core.EncodeRandaoParSignedData(randao2, 1)

	require.Equal(t, randao1, randao2)
	require.Equal(t, data1, data2)
}

func TestEncodeRandaoAggSignedData(t *testing.T) {
	randao1 := testutil.RandomEth2Signature()

	data1 := core.EncodeRandaoAggSignedData(randao1)
	randao2 := core.DecodeRandaoAggSignedData(data1)
	data2 := core.EncodeRandaoAggSignedData(randao2)

	require.Equal(t, randao1, randao2)
	require.Equal(t, data1, data2)
}

func TestEncodeProposerFetchArg(t *testing.T) {
	proDuty1 := testutil.RandomProposerDuty(t)

	arg1, err := core.EncodeProposerFetchArg(proDuty1)
	require.NoError(t, err)

	proDuty2, err := core.DecodeProposerFetchArg(arg1)
	require.NoError(t, err)

	arg2, err := core.EncodeProposerFetchArg(proDuty2)
	require.NoError(t, err)

	require.Equal(t, arg1, arg2)
	require.Equal(t, proDuty1, proDuty2)
}

func TestEncodeProposerUnsignedData(t *testing.T) {
	proData1 := &spec.VersionedBeaconBlock{
		Version: spec.DataVersionPhase0,
		Phase0:  testutil.RandomBeaconBlock(),
	}

	data1, err := core.EncodeProposerUnsignedData(proData1)
	require.NoError(t, err)

	proData2, err := core.DecodeProposerUnsignedData(data1)
	require.NoError(t, err)

	data2, err := core.EncodeProposerUnsignedData(proData2)
	require.NoError(t, err)

	require.Equal(t, proData1, proData2)
	require.Equal(t, data1, data2)
}

func TestEncodeBlockParSignedData(t *testing.T) {
	block1 := &spec.VersionedSignedBeaconBlock{
		Version: spec.DataVersionPhase0,
		Phase0: &eth2p0.SignedBeaconBlock{
			Message:   testutil.RandomBeaconBlock(),
			Signature: testutil.RandomEth2Signature(),
		},
	}

	data1, err := core.EncodeBlockParSignedData(block1, 0)
	require.NoError(t, err)

	block2, err := core.DecodeBlockParSignedData(data1)
	require.NoError(t, err)

	data2, err := core.EncodeBlockParSignedData(block2, 0)
	require.NoError(t, err)

	require.Equal(t, block1, block2)
	require.Equal(t, data1, data2)
}
