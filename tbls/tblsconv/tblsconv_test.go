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
	"math/rand"
	"testing"
	"time"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/tbls"
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

func TestShareToSecret(t *testing.T) {
	_, shares, err := tbls.GenerateTSS(3, 4, rand.New(rand.NewSource(time.Now().UnixNano())))
	require.NoError(t, err)

	msg := []byte("test data")

	for _, share := range shares {
		secret, err := tblsconv.ShareToSecret(share)
		require.NoError(t, err)

		psig, err := tbls.PartialSign(share, msg)
		require.NoError(t, err)

		sig, err := tbls.Sign(secret, msg)
		require.NoError(t, err)

		pdata := tblsconv.SigToBytes(&bls_sig.Signature{Value: psig.Signature})
		data := tblsconv.SigToBytes(sig)

		require.Equal(t, pdata, data)
	}
}

func TestSecretToBytes(t *testing.T) {
	_, shares, err := tbls.GenerateTSS(3, 4, rand.New(rand.NewSource(time.Now().UnixNano())))
	require.NoError(t, err)

	for _, share := range shares {
		secret, err := tblsconv.ShareToSecret(share)
		require.NoError(t, err)

		b, err := tblsconv.SecretToBytes(secret)
		require.NoError(t, err)

		result, err := tblsconv.SecretFromBytes(b)
		require.NoError(t, err)
		require.Equal(t, secret, result)
	}
}

func TestShareToSecret_ZeroPadding(t *testing.T) {
	_, shares, err := tbls.GenerateTSS(3, 4, rand.New(rand.NewSource(96)))
	require.NoError(t, err)

	msg := []byte("test data")

	for _, share := range shares {
		secret, err := tblsconv.ShareToSecret(share)
		require.NoError(t, err)

		psig, err := tbls.PartialSign(share, msg)
		require.NoError(t, err)

		sig, err := tbls.Sign(secret, msg)
		require.NoError(t, err)

		pdata := tblsconv.SigToBytes(&bls_sig.Signature{Value: psig.Signature})
		data := tblsconv.SigToBytes(sig)

		require.Equal(t, pdata, data)
	}
}
