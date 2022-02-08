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

package krypto

import (
	"encoding/binary"
	"math/big"

	"github.com/coinbase/kryptology/pkg/core/curves"
	share "github.com/coinbase/kryptology/pkg/sharing/v1"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
)

// PubShare is a public share corresponding to a secret share.
type PubShare struct {
	Identifier byte
	Value      *bls_sig.PublicKey
}

// TSS (threshold signing scheme) wraps PubKey (PublicKey), PubShares (the public shares corresponding to each secret share)
// and NumShares (number of shares).
type TSS struct {
	PubKey    *bls_sig.PublicKey
	PubShares []*PubShare
	NumShares uint
}

// GenerateTSS returns a new instance of threshold signing scheme and associated SecretKeyShares.
func GenerateTSS(t, n uint) (*TSS, []*bls_sig.SecretKeyShare, error) {
	pubKey, secret, err := BlsScheme.Keygen()
	if err != nil {
		return nil, nil, errors.Wrap(err, "BLS Key Generation")
	}

	sks, pubshares, err := generateSecretShares(*secret, t, n)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Generate Secret Shares")
	}

	return &TSS{PubKey: pubKey, PubShares: pubshares, NumShares: n}, sks, nil
}

// generateSecretShares creates []*SecretKeyShare and []*PubShare over the given SecretKey.
func generateSecretShares(sk bls_sig.SecretKey, t, n uint) ([]*bls_sig.SecretKeyShare, []*PubShare, error) {
	scheme, err := share.NewFeldman(uint32(t), uint32(n), share.Bls12381G1())
	if err != nil {
		return nil, nil, errors.Wrap(err, "New Feldman VSS")
	}

	secretBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, errors.Wrap(err, "Marshalling Secret Key")
	}

	verifiers, shares, err := scheme.Split(secretBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Split Secret Key")
	}

	sks := make([]*bls_sig.SecretKeyShare, len(shares))
	pbs := make([]*PubShare, len(shares))
	for i, s := range shares {
		skbin := make([]byte, 33)
		copy(skbin, s.Value.Bytes())
		skbin[32] = uint8(s.Identifier)

		sks[i] = &bls_sig.SecretKeyShare{}
		if err := sks[i].UnmarshalBinary(skbin); err != nil {
			return nil, nil, errors.Wrap(err, "Unmarshalling shamir share")
		}

		pbs[i], err = getPubShare(share.Bls12381G1().Params().N, s, verifiers)
		if err != nil {
			return nil, nil, errors.Wrap(err, "Get Public Share")
		}
	}

	return sks, pbs, nil
}

// getPubShare creates PubShare corresponding to a secret share with given verifiers.
func getPubShare(n *big.Int, share *share.ShamirShare, verifiers []*share.ShareVerifier) (*PubShare, error) {
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

	g1Point, err := KeyGroup.FromUncompressed(rhs.Bytes())
	if err != nil {
		return nil, err
	}

	pubshare := &PubShare{}
	err = pubshare.Value.UnmarshalBinary(KeyGroup.ToCompressed(g1Point))
	if err != nil {
		return nil, err
	}
	pubshare.Identifier = uint8(share.Identifier)

	return pubshare, nil
}
