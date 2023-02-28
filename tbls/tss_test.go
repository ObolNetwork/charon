// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	b.StopTimer()

	// Create b.N unique signatures to verify.

	type tuple struct {
		PubKey *bls_sig.PublicKey
		Secret *bls_sig.SecretKey
		Sig    *bls_sig.Signature
		Msg    []byte
	}

	var tuples []tuple
	for i := 0; i < b.N; i++ {
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

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		tuple := tuples[i]
		result, err := tbls.Verify(tuple.PubKey, tuple.Msg, tuple.Sig)
		require.NoError(b, err)
		require.Equal(b, true, result)
	}
}
