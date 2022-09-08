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

package tbls_test

import (
	"crypto/rand"
	"testing"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
)

func TestGenerateTSS(t *testing.T) {
	threshold := 3
	shares := 5

	tss, secrets, err := tbls.GenerateTSS(threshold, shares, rand.Reader)
	require.NoError(t, err)
	require.NotNil(t, tss)
	require.NotNil(t, secrets)

	require.Equal(t, threshold, tss.Threshold())
	require.Equal(t, shares, tss.NumShares())
}

func TestCombineShares(t *testing.T) {
	const (
		threshold = 3
		total     = 5
	)

	_, secret, err := tbls.Keygen()
	require.NoError(t, err)

	shares, _, err := tbls.SplitSecret(secret, threshold, total, rand.Reader)
	require.NoError(t, err)

	result, err := tbls.CombineShares(shares, threshold, total)
	require.NoError(t, err)

	expect, err := secret.MarshalBinary()
	require.NoError(t, err)
	actual, err := result.MarshalBinary()
	require.NoError(t, err)

	require.Equal(t, expect, actual)
}

func TestAggregateSignatures(t *testing.T) {
	threshold := 3
	shares := 5

	tss, secrets, err := tbls.GenerateTSS(threshold, shares, rand.Reader)
	require.NoError(t, err)

	msg := []byte("Hello Obol")
	partialSigs := make([]*bls_sig.PartialSignature, len(secrets))
	for i, secret := range secrets {
		psig, err := tbls.PartialSign(secret, msg)
		require.NoError(t, err)

		partialSigs[i] = psig

		pubshare := tss.PublicShare(int(psig.Identifier))

		ok, err := tbls.Verify(pubshare, msg, &bls_sig.Signature{Value: psig.Signature})
		require.NoError(t, err)
		require.True(t, ok)
	}

	sig, _, err := tbls.VerifyAndAggregate(tss, partialSigs, msg)
	require.NoError(t, err)

	result, err := tbls.Verify(tss.PublicKey(), msg, sig)
	require.NoError(t, err)
	require.Equal(t, true, result)
}

func BenchmarkVerify(b *testing.B) {
	type tuple struct {
		PubKey *bls_sig.PublicKey
		Secret *bls_sig.SecretKey
		Sig    *bls_sig.Signature
		Msg    []byte
	}

	const count = 100 // Create 100 different signatures to verify
	var tuples []tuple
	for i := 0; i < count; i++ {
		pubkey, secret, err := tbls.Keygen()
		require.NoError(b, err)

		msg := testutil.RandomBytes32()

		sig, err := tbls.Sign(secret, msg)
		require.NoError(b, err)

		tuples = append(tuples, tuple{
			PubKey: pubkey,
			Secret: secret,
			Sig:    sig,
			Msg:    msg,
		})
	}

	b.Run("verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tuple := tuples[i%count]
			result, err := tbls.Verify(tuple.PubKey, tuple.Msg, tuple.Sig)
			require.NoError(b, err)
			require.Equal(b, true, result)
		}
	})
}
