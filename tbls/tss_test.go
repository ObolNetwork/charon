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

		pubshare, err := tss.PublicShare(int(psig.Identifier))
		require.NoError(t, err)

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
