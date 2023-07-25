// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package k1util_test

import (
	"encoding/hex"
	"math/rand"
	"os"
	"path"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/k1util"
)

const (
	privKey1 = "41d3ff12045b73c870529fe44f70dca2745bafbe1698ffc3c8759eef3cfbaee1"
	pubKey1  = "02bc8e7cdb50e0ffd52a54faf984d6ac8fe5ee6856d38a5f8acd9bd33fc9c7d50d"
	digest1  = "52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649" // 32 byte digest.
	sig1     = "e08097bed6dc40d70aa0076f9d8250057566cdf40c652b3785ad9c06b1e38d584f8f331bf46f68e3737823a3bda905e90ca96735d510a6934b215753c09acec201"
)

// TestLegacyGethCrypto ensures compatibility with github.com/ethereum/go-ethereum/crypto.
// But since we do not want the dependency, it has been commented out.
// func TestLegacyGethCrypto(t *testing.T) {
//	key, err := ecdsa.GenerateKey(crypto.S256(), rand.New(rand.NewSource(0)))
//	require.NoError(t, err)
//
//	require.Equal(t, fromHex(t, privKey1), crypto.FromECDSA(key))
//	require.Equal(t, fromHex(t, pubKey1), crypto.CompressPubkey(&key.PublicKey))
//
//	digest := fromHex(t, digest1)
//
//	sig, err := crypto.Sign(digest, key)
//	require.NoError(t, err)
//	require.Equal(t, fromHex(t, sig1), sig)
//
//	ok := crypto.VerifySignature(
//		crypto.CompressPubkey(&key.PublicKey),
//		digest,
//		sig[:len(sig)-1])
//	require.True(t, ok)
// }

func TestK1Util(t *testing.T) {
	key := k1.PrivKeyFromBytes(fromHex(t, privKey1))

	require.Equal(t, fromHex(t, privKey1), key.Serialize())
	require.Equal(t, fromHex(t, pubKey1), key.PubKey().SerializeCompressed())

	digest := fromHex(t, digest1)

	sig, err := k1util.Sign(key, digest)
	require.NoError(t, err)
	require.Equal(t, fromHex(t, sig1), sig)

	ok, err := k1util.Verify65(key.PubKey(), digest, sig)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = k1util.Verify64(key.PubKey(), digest, sig[:len(sig)-1])
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

	ok, err := k1util.Verify65(key.PubKey(), digest, sig)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = k1util.Verify64(key.PubKey(), digest, sig[:len(sig)-1])
	require.NoError(t, err)
	require.True(t, ok)

	recovered, err := k1util.Recover(
		digest,
		sig)
	require.NoError(t, err)
	require.True(t, key.PubKey().IsEqual(recovered))
}

func TestLoad(t *testing.T) {
	key, err := k1.GeneratePrivateKey()
	require.NoError(t, err)
	filePath := path.Join(t.TempDir(), "charon-enr-private-key")

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := k1util.Load("nonexistent-file")
		require.ErrorContains(t, err, "read private key from disk")
	})

	t.Run("invalid hex encoded file", func(t *testing.T) {
		invalidHexStr := "abcXYZ123" // Invalid hex string
		err = os.WriteFile(filePath, []byte(invalidHexStr), 0o600)
		require.NoError(t, err)

		_, err := k1util.Load(filePath)
		require.ErrorContains(t, err, "decode private key hex")
	})

	t.Run("valid hex strings", func(t *testing.T) {
		hexStrs := []string{
			hex.EncodeToString(key.Serialize()) + "\n",   // Hex string ending with '\n'
			hex.EncodeToString(key.Serialize()) + "\r\n", // Hex string ending with '\r\n'
			hex.EncodeToString(key.Serialize()) + " ",    // Hex string ending with a space
			hex.EncodeToString(key.Serialize()),          // Hex string
		}

		for _, hexStr := range hexStrs {
			err = os.WriteFile(filePath, []byte(hexStr), 0o600)
			require.NoError(t, err)

			pkey, err := k1util.Load(filePath)
			require.NoError(t, err)
			require.Equal(t, key, pkey)
		}
	})
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
			ok, err := k1util.Verify64(
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
