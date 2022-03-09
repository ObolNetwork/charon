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

package tblsconv_test

import (
	"testing"

	"github.com/dB2510/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/tbls/tblsconv"
)

func TestCoreKey(t *testing.T) {
	tblsKey1, _, err := bls_sig.NewSigEth2().Keygen()
	require.NoError(t, err)

	coreKey, err := tblsconv.KeyToCore(tblsKey1)
	require.NoError(t, err)

	tblsKey2, err := tblsconv.KeyFromCore(coreKey)
	require.NoError(t, err)

	b1, err := tblsKey1.MarshalBinary()
	require.NoError(t, err)
	b2, err := tblsKey2.MarshalBinary()
	require.NoError(t, err)

	require.Equal(t, b1, b2)
}

func TestETHKey(t *testing.T) {
	tblsKey1, _, err := bls_sig.NewSigEth2().Keygen()
	require.NoError(t, err)

	eth2Key, err := tblsconv.KeyToETH2(tblsKey1)
	require.NoError(t, err)

	tblsKey2, err := tblsconv.KeyFromETH2(eth2Key)
	require.NoError(t, err)

	b1, err := tblsKey1.MarshalBinary()
	require.NoError(t, err)
	b2, err := tblsKey2.MarshalBinary()
	require.NoError(t, err)

	require.Equal(t, b1, b2)
}

func TestSig(t *testing.T) {
	scheme := bls_sig.NewSigEth2()
	_, secret, err := scheme.Keygen()
	require.NoError(t, err)

	sig1, err := scheme.Sign(secret, []byte("msg"))
	require.NoError(t, err)

	eth2Sig := tblsconv.SigToETH2(sig1)
	require.NoError(t, err)

	sig2, err := tblsconv.SigFromETH2(eth2Sig)
	require.NoError(t, err)

	b1 := tblsconv.SigToBytes(sig1)
	b2 := tblsconv.SigToBytes(sig2)

	sig3, err := tblsconv.SigFromBytes(b2)
	require.NoError(t, err)

	b3 := tblsconv.SigToBytes(sig3)

	require.Equal(t, b1, b2)
	require.Equal(t, b1, b3)
}
