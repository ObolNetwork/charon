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

func TestAggSignedData_Equal(t *testing.T) {
	testAggSignedData1 := core.AggSignedData{
		Data:      []byte("test data"),
		Signature: testutil.RandomCoreSignature(),
	}

	testAggSignedData2 := core.AggSignedData{
		Data:      []byte("test data"),
		Signature: testAggSignedData1.Signature,
	}

	testAggSignedData3 := core.AggSignedData{
		Data:      []byte("test data 3"),
		Signature: testutil.RandomCoreSignature(),
	}

	testAggSignedData4 := core.AggSignedData{
		Data:      []byte("test data"),
		Signature: testutil.RandomCoreSignature(),
	}

	testAggSignedData5 := core.AggSignedData{
		Data:      []byte("test data 5"),
		Signature: testutil.RandomCoreSignature(),
	}

	require.True(t, testAggSignedData1.Equal(testAggSignedData2))
	require.False(t, testAggSignedData1.Equal(testAggSignedData3))
	require.False(t, testAggSignedData1.Equal(testAggSignedData4))
	require.False(t, testAggSignedData1.Equal(testAggSignedData5))
}
