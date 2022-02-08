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

package krypto_test

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"

	"github.com/coinbase/kryptology/pkg/core/curves"
	share "github.com/coinbase/kryptology/pkg/sharing/v1"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/crypto/krypto"
)

type Pubshare struct {
	Identifier uint32          `json:"identifier"` // x-coordinate
	Value      *curves.EcPoint `json:"value"`      // y-coordinate
}

func getPubShares(n *big.Int, share *share.ShamirShare, verifiers []*share.ShareVerifier, threshold int) (*Pubshare, error) {
	if len(verifiers) < threshold {
		return nil, fmt.Errorf("not enough verifiers to check")
	}
	field := curves.NewField(n)

	xBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(xBytes, share.Identifier)
	x := field.ElementFromBytes(xBytes)

	i := share.Value.Modulus.One()

	// c_0
	rhs := verifiers[0]

	// Compute the sum of products
	// c_0 * c_1^i * c_2^{i^2} * c_3^{i^3} ... c_t^{i_t}
	for j := 1; j < len(verifiers); j++ {
		// i *= x
		i = i.Mul(x)

		c, err := verifiers[j].ScalarMult(i.Value)
		if err != nil {
			return nil, err
		}

		// ... * c_j^{i^j}
		rhs, err = rhs.Add(c)
		if err != nil {
			return nil, err
		}
	}

	value := &curves.EcPoint{Curve: rhs.Curve, X: rhs.X, Y: rhs.Y}

	return &Pubshare{Identifier: share.Identifier, Value: value}, nil
}

func TestKrypto(t *testing.T) {
	scheme, err := share.NewFeldman(3, 5, share.Bls12381G1())
	n := share.Bls12381G1().Params().N
	require.NoError(t, err)
	require.NotNil(t, scheme)

	secret := []byte("TestingKrypto")
	verifiers, shares, err := scheme.Split(secret)
	require.NoError(t, err)
	for _, s := range shares {
		ok, err := scheme.Verify(s, verifiers)
		require.Nil(t, err)
		require.True(t, ok)
	}

	shabin := make([]byte, 33)
	copy(shabin, shares[0].Value.Bytes())
	shabin[32] = uint8(shares[0].Identifier)
	sks := &bls_sig.SecretKeyShare{}
	err = sks.UnmarshalBinary(shabin)
	require.NoError(t, err)
	t.Log(sks)
	t.Log("Identifier: ", shares[0].Identifier)
	t.Log("Value: ", shares[0].Value)

	msg := []byte("Hello Obol")
	psig, err := krypto.BlsScheme.PartialSign(sks, msg)
	sig := &bls_sig.Signature{Value: *psig.Signature}
	require.NotNil(t, sig)
	require.NotNil(t, psig)
	require.NoError(t, err)

	v, err := scheme.Verify(shares[0], verifiers)
	require.NoError(t, err)
	require.Equal(t, v, true)

	pbs, err := getPubShares(n, shares[0], verifiers, 3)
	require.NoError(t, err)
	require.NotNil(t, pbs)
	t.Log("public share: ", pbs.Value.Curve.Params().Name)

	pubshare := &bls_sig.PublicKey{}
	require.Equal(t, pbs.Value.IsOnCurve(), true)
	bin := pbs.Value.Bytes()
	g1Point, err := krypto.KeyGroup.FromUncompressed(bin)
	require.NoError(t, err)
	require.NotNil(t, g1Point)
	err = pubshare.UnmarshalBinary(krypto.KeyGroup.ToCompressed(g1Point))
	require.NoError(t, err)

	result, err := krypto.BlsScheme.Verify(pubshare, msg, sig)
	require.NoError(t, err)
	require.Equal(t, result, true)
}
