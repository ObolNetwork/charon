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

	"github.com/coinbase/kryptology/pkg/core/curves"
	share "github.com/coinbase/kryptology/pkg/sharing/v1"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
)

// PubShare is a public share corresponding to a secret share.
type PubShare struct {
	identifier byte
	Value      *bls_sig.PublicKey
}

// TSS (threshold signing scheme) wraps pubKey (PublicKey), verifiers (the public shares corresponding to each secret share)
// and threshold (number of shares).
type TSS struct {
	pubKey    *bls_sig.PublicKey
	verifiers []*share.ShareVerifier
	numShares int
}

// GenerateTSS returns a new random instance of threshold signing scheme and associated SecretKeyShares.
// It generates n number of secret key shares where t of them can be combined to sign a message.
func GenerateTSS(t, n int) (*TSS, []*bls_sig.SecretKeyShare, error) {
	pubKey, secret, err := BlsScheme.Keygen()
	if err != nil {
		return nil, nil, errors.Wrap(err, "bls key generation")
	}

	sks, verifiers, err := generateSecretShares(*secret, t, n)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generate secret shares")
	}

	return &TSS{pubKey: pubKey, verifiers: verifiers, numShares: n}, sks, nil
}

// AggregateSignatures aggregates partial signatures over the given message.
// Returns aggregated signatures and slice of signers identifiers that had valid partial signatures.
func AggregateSignatures(tss *TSS, partialSigs []*bls_sig.PartialSignature, msg []byte) (*bls_sig.Signature, []byte, error) {
	threshold := len(tss.verifiers)
	if len(partialSigs) < threshold {
		return nil, nil, errors.New("insufficient signatures")
	}

	var (
		signers     []byte
		validShares []*PubShare
	)

	for _, psig := range partialSigs {
		if len(validShares) >= threshold {
			break
		}

		pubShare, err := getPubShare(uint32(psig.Identifier), tss.verifiers)
		if err != nil {
			return nil, nil, errors.Wrap(err, "get Public Share")
		}

		sig := &bls_sig.Signature{Value: *psig.Signature}
		result, err := BlsScheme.Verify(pubShare.Value, msg, sig)
		if result && err == nil {
			validShares = append(validShares, pubShare)
			signers = append(signers, psig.Identifier)
		}
	}

	if len(validShares) < threshold {
		return nil, nil, errors.New("insufficient valid signatures")
	}

	aggregatedSig, err := BlsScheme.CombineSignatures(partialSigs...)
	if err != nil {
		return nil, nil, errors.Wrap(err, "aggregate signatures")
	}

	return aggregatedSig, signers, nil
}

// generateSecretShares creates []*SecretKeyShare and []*PubShare over the given SecretKey.
func generateSecretShares(secret bls_sig.SecretKey, t, n int) ([]*bls_sig.SecretKeyShare, []*share.ShareVerifier, error) {
	scheme, err := share.NewFeldman(uint32(t), uint32(n), share.Bls12381G1())
	if err != nil {
		return nil, nil, errors.Wrap(err, "New Feldman VSS")
	}

	secretBytes, err := secret.MarshalBinary()
	if err != nil {
		return nil, nil, errors.Wrap(err, "Marshalling Secret Key")
	}

	verifiers, shares, err := scheme.Split(secretBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Split Secret Key")
	}

	sks := make([]*bls_sig.SecretKeyShare, len(shares))

	for i, s := range shares {
		skbin := make([]byte, 33)
		copy(skbin, s.Value.Bytes())
		skbin[32] = uint8(s.Identifier)

		sks[i] = &bls_sig.SecretKeyShare{}
		if err := sks[i].UnmarshalBinary(skbin); err != nil {
			return nil, nil, errors.Wrap(err, "Unmarshalling shamir share")
		}
	}

	return sks, verifiers, nil
}

// getPubShare creates PubShare corresponding to a secret share with given verifiers.
func getPubShare(identifier uint32, verifiers []*share.ShareVerifier) (*PubShare, error) {
	field := curves.NewField(share.Bls12381G1().N)

	xBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(xBytes, identifier)
	x := field.ElementFromBytes(xBytes)
	i := field.One()

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

	pks := &bls_sig.PublicKey{}
	err = pks.UnmarshalBinary(KeyGroup.ToCompressed(g1Point))
	if err != nil {
		return nil, err
	}

	return &PubShare{identifier: uint8(identifier), Value: pks}, nil
}
