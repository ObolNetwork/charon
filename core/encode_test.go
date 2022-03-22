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

package core_test

import (
	"testing"

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
