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

func TestEncodeAttesterDutyDefinition(t *testing.T) {
	attDuty1 := testutil.RandomAttestationDuty(t)

	arg1, err := core.EncodeAttesterDutyDefinition(attDuty1)
	require.NoError(t, err)

	attDuty2, err := core.DecodeAttesterDutyDefinition(arg1)
	require.NoError(t, err)

	arg2, err := core.EncodeAttesterDutyDefinition(attDuty2)
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

func TestEncodeAttesterShareSignedData(t *testing.T) {
	att1 := testutil.RandomAttestation()

	data1, err := core.EncodeAttestationShareSignedData(att1, 1)
	require.NoError(t, err)

	att2, err := core.DecodeAttestationShareSignedData(data1)
	require.NoError(t, err)

	data2, err := core.EncodeAttestationShareSignedData(att2, 1)
	require.NoError(t, err)

	require.Equal(t, att1, att2)
	require.Equal(t, data1, data2)
}

func TestEncodeAttesterGroupSignedData(t *testing.T) {
	att1 := testutil.RandomAttestation()

	data1, err := core.EncodeAttestationGroupSignedData(att1)
	require.NoError(t, err)

	att2, err := core.DecodeAttestationGroupSignedData(data1)
	require.NoError(t, err)

	data2, err := core.EncodeAttestationGroupSignedData(att2)
	require.NoError(t, err)

	require.Equal(t, att1, att2)
	require.Equal(t, data1, data2)
}

func TestEncodeRandaoShareSignedData(t *testing.T) {
	randao1 := testutil.RandomEth2Signature()

	data1 := core.EncodeRandaoShareSignedData(randao1, 1)
	randao2 := core.DecodeRandaoShareSignedData(data1)
	data2 := core.EncodeRandaoShareSignedData(randao2, 1)

	require.Equal(t, randao1, randao2)
	require.Equal(t, data1, data2)
}

func TestEncodeRandaoGroupSignedData(t *testing.T) {
	randao1 := testutil.RandomEth2Signature()

	data1 := core.EncodeRandaoGroupSignedData(randao1)
	randao2 := core.DecodeRandaoGroupSignedData(data1)
	data2 := core.EncodeRandaoGroupSignedData(randao2)

	require.Equal(t, randao1, randao2)
	require.Equal(t, data1, data2)
}

func TestEncodeProposerDutyDefinition(t *testing.T) {
	proDuty1 := testutil.RandomProposerDuty(t)

	arg1, err := core.EncodeProposerDutyDefinition(proDuty1)
	require.NoError(t, err)

	proDuty2, err := core.DecodeProposerDutyDefinition(arg1)
	require.NoError(t, err)

	arg2, err := core.EncodeProposerDutyDefinition(proDuty2)
	require.NoError(t, err)

	require.Equal(t, arg1, arg2)
	require.Equal(t, proDuty1, proDuty2)
}

func TestEncodeProposerUnsignedData(t *testing.T) {
	proData1 := &spec.VersionedBeaconBlock{
		Version: spec.DataVersionPhase0,
		Phase0:  testutil.RandomPhase0BeaconBlock(),
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

func TestEncodeBlockShareSignedData(t *testing.T) {
	block1 := &spec.VersionedSignedBeaconBlock{
		Version: spec.DataVersionPhase0,
		Phase0: &eth2p0.SignedBeaconBlock{
			Message:   testutil.RandomPhase0BeaconBlock(),
			Signature: testutil.RandomEth2Signature(),
		},
	}

	data1, err := core.EncodeBlockShareSignedData(block1, 0)
	require.NoError(t, err)

	block2, err := core.DecodeBlockShareSignedData(data1)
	require.NoError(t, err)

	data2, err := core.EncodeBlockShareSignedData(block2, 0)
	require.NoError(t, err)

	require.Equal(t, block1, block2)
	require.Equal(t, data1, data2)
}

func TestEncodeBlockGroupSignedData(t *testing.T) {
	block1 := &spec.VersionedSignedBeaconBlock{
		Version: spec.DataVersionPhase0,
		Phase0: &eth2p0.SignedBeaconBlock{
			Message:   testutil.RandomPhase0BeaconBlock(),
			Signature: testutil.RandomEth2Signature(),
		},
	}

	data1, err := core.EncodeBlockGroupSignedData(block1)
	require.NoError(t, err)

	block2, err := core.DecodeBlockGroupSignedData(data1)
	require.NoError(t, err)

	data2, err := core.EncodeBlockGroupSignedData(block2)
	require.NoError(t, err)

	require.Equal(t, block1, block2)
	require.Equal(t, data1, data2)
}
