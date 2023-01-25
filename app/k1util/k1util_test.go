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

package k1util_test

import (
	"crypto/ecdsa"
	"encoding/hex"
	"math/rand"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/k1util"
)

const (
	privKey1 = "41d3ff12045b73c870529fe44f70dca2745bafbe1698ffc3c8759eef3cfbaee1"
	pubKey1  = "02bc8e7cdb50e0ffd52a54faf984d6ac8fe5ee6856d38a5f8acd9bd33fc9c7d50d"
	digest1  = "52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649" // 32 byte digest.
	sig1     = "e08097bed6dc40d70aa0076f9d8250057566cdf40c652b3785ad9c06b1e38d584f8f331bf46f68e3737823a3bda905e90ca96735d510a6934b215753c09acec201"
)

func TestLegacyGethCrypto(t *testing.T) {
	key, err := ecdsa.GenerateKey(crypto.S256(), rand.New(rand.NewSource(0)))
	require.NoError(t, err)

	require.Equal(t, fromHex(t, privKey1), crypto.FromECDSA(key))
	require.Equal(t, fromHex(t, pubKey1), crypto.CompressPubkey(&key.PublicKey))

	digest := fromHex(t, digest1)

	sig, err := crypto.Sign(digest, key)
	require.NoError(t, err)
	require.Equal(t, fromHex(t, sig1), sig)

	ok := crypto.VerifySignature(
		crypto.CompressPubkey(&key.PublicKey),
		digest,
		sig[:len(sig)-1])
	require.True(t, ok)
}

func TestK1Util(t *testing.T) {
	key := k1.PrivKeyFromBytes(fromHex(t, privKey1))

	require.Equal(t, fromHex(t, privKey1), key.Serialize())
	require.Equal(t, fromHex(t, pubKey1), key.PubKey().SerializeCompressed())

	digest := fromHex(t, digest1)

	sig, err := k1util.Sign(key, digest)
	require.NoError(t, err)
	require.Equal(t, fromHex(t, sig1), sig)

	ok, err := k1util.Verify(
		key.PubKey(),
		digest,
		sig[:len(sig)-1])
	require.NoError(t, err)
	require.True(t, ok)

	recovered, err := k1util.Recover(
		digest,
		sig)
	require.NoError(t, err)
	require.True(t, key.PubKey().IsEqual(recovered))
}

func TestRandom(t *testing.T) {
	key, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	digest := make([]byte, 32)
	_, _ = rand.Read(digest)

	sig, err := k1util.Sign(key, digest)
	require.NoError(t, err)

	ok, err := k1util.Verify(
		key.PubKey(),
		digest,
		sig[:len(sig)-1])
	require.NoError(t, err)
	require.True(t, ok)

	recovered, err := k1util.Recover(
		digest,
		sig)
	require.NoError(t, err)
	require.True(t, key.PubKey().IsEqual(recovered))
}

// BenchmarkRecoverVerify benchmarks recovery vs verification.
//
// TL;DR: verify is slightly faster than recover, both in the order of hundreds of microseconds.
func BenchmarkRecoverVerify(b *testing.B) {
	b.StopTimer()

	key, err := k1.GeneratePrivateKey()
	require.NoError(b, err)

	digest := make([]byte, 32)
	_, _ = rand.Read(digest)

	sig, err := k1util.Sign(key, digest)
	require.NoError(b, err)

	b.StartTimer()

	b.Run("recover", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			recovered, err := k1util.Recover(
				digest,
				sig)
			require.NoError(b, err)
			require.True(b, key.PubKey().IsEqual(recovered))
		}
	})

	b.Run("verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ok, err := k1util.Verify(
				key.PubKey(),
				digest,
				sig[:len(sig)-1])
			require.NoError(b, err)
			require.True(b, ok)
		}
	})
}

func fromHex(t *testing.T, hexStr string) []byte {
	t.Helper()
	b, err := hex.DecodeString(hexStr)
	require.NoError(t, err)

	return b
}
