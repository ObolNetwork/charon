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

package crypto

import (
	"io"

	"github.com/coinbase/kryptology/pkg/core/curves"
	bls12381 "github.com/coinbase/kryptology/pkg/core/curves/native/bls12-381"
	share "github.com/coinbase/kryptology/pkg/sharing"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
)

var (
	// pairing is the BLS12-381 Engine initialising G1 and G2 groups.
	pairing = bls12381.NewEngine()

	// keyGroup is the G1 group.
	keyGroup = pairing.G1

	// blsScheme is the BLS12-381 ETH2 signature scheme with standard domain separation tag used for signatures.
	// blsScheme uses proofs of possession to mitigate rogue-key attacks.
	// see: https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-03#section-4.2.3
	blsScheme = bls_sig.NewSigEth2()
)

// PubShare is a public share corresponding to a secret share.
type PubShare struct {
	identifier byte
	Value      *bls_sig.PublicKey
}

// TSS (threshold signing scheme) wraps PubKey (PublicKey), Verifiers (the public shares corresponding to each secret share)
// and threshold (number of shares).
type TSS struct {
	PubKey    *bls_sig.PublicKey
	Verifier  *share.FeldmanVerifier
	NumShares int
}

// Threshold returns the secret sharing threshold.
func (t TSS) Threshold() int {
	return len(t.Verifier.Commitments)
}

// GenerateTSS returns a new random instance of threshold signing scheme and associated SecretKeyShares.
// It generates n number of secret key shares where t of them can be combined to sign a message.
func GenerateTSS(t, n int, reader io.Reader) (TSS, []*bls_sig.SecretKeyShare, error) {
	ikm := make([]byte, 32)
	_, _ = reader.Read(ikm)
	pubKey, secret, err := blsScheme.KeygenWithSeed(ikm)
	if err != nil {
		return TSS{}, nil, errors.Wrap(err, "bls key generation")
	}

	sks, verifier, err := generateSecretShares(*secret, t, n, reader)
	if err != nil {
		return TSS{}, nil, errors.Wrap(err, "generate secret shares")
	}

	return TSS{PubKey: pubKey, Verifier: verifier, NumShares: n}, sks, nil
}

// AggregateSignatures aggregates partial signatures over the given message.
// Returns aggregated signatures and slice of signers identifiers that had valid partial signatures.
func AggregateSignatures(tss TSS, partialSigs []*bls_sig.PartialSignature, msg []byte) (*bls_sig.Signature, []byte, error) {
	threshold := tss.Threshold()
	if len(partialSigs) < threshold {
		return nil, nil, errors.New("insufficient signatures")
	}

	var (
		signers     []byte
		validShares []*PubShare
	)

	for _, psig := range partialSigs {
		// TODO(dhruv): add break condition if valid shares >= threshold
		pubShare, err := getPubShare(uint32(psig.Identifier), tss.Verifier)
		if err != nil {
			return nil, nil, errors.Wrap(err, "get Public Share")
		}

		sig := &bls_sig.Signature{Value: *psig.Signature}
		ok, err := blsScheme.Verify(pubShare.Value, msg, sig)
		if err != nil || !ok {
			continue
		}
		validShares = append(validShares, pubShare)
		signers = append(signers, psig.Identifier)
	}

	if len(validShares) < threshold {
		return nil, nil, errors.New("insufficient valid signatures")
	}

	aggregatedSig, err := blsScheme.CombineSignatures(partialSigs...)
	if err != nil {
		return nil, nil, errors.Wrap(err, "aggregate signatures")
	}

	return aggregatedSig, signers, nil
}

// Verify verifies the given signature(sig) on message(msg) with given public key (pk).
func Verify(pk *bls_sig.PublicKey, msg []byte, sig *bls_sig.Signature) (bool, error) {
	return blsScheme.Verify(pk, msg, sig)
}

// PartialSign signs given message(msg) using given Secret Key Share(sks) and returns a Partial Signature.
func PartialSign(sks *bls_sig.SecretKeyShare, msg []byte) (*bls_sig.PartialSignature, error) {
	return blsScheme.PartialSign(sks, msg)
}

// generateSecretShares splits the secret and returns n secret shares and t verifiers.
func generateSecretShares(secret bls_sig.SecretKey, t, n int, reader io.Reader) ([]*bls_sig.SecretKeyShare, *share.FeldmanVerifier, error) {
	scheme, err := share.NewFeldman(uint32(t), uint32(n), curves.BLS12381G1())
	if err != nil {
		return nil, nil, errors.Wrap(err, "new Feldman VSS")
	}

	secretBytes, err := secret.MarshalBinary()
	if err != nil {
		return nil, nil, errors.Wrap(err, "marshalling Secret Key")
	}

	secretScaler, err := curves.BLS12381G1().NewScalar().SetBytes(secretBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "convert to scaler")
	}

	verifier, shares, err := scheme.Split(secretScaler, reader)
	if err != nil {
		return nil, nil, errors.Wrap(err, "split Secret Key")
	}

	sks := make([]*bls_sig.SecretKeyShare, len(shares))

	for i, s := range shares {
		// ref: https://github.com/coinbase/kryptology/blob/71ffd4cbf01951cd0ee056fc7b45b13ffb178330/pkg/signatures/bls/bls_sig/lib.go#L26
		skbin := s.Value
		skbin = append(skbin, byte(s.Id))
		sks[i] = &bls_sig.SecretKeyShare{}
		if err := sks[i].UnmarshalBinary(skbin); err != nil {
			return nil, nil, errors.Wrap(err, "unmarshalling shamir share")
		}
	}

	return sks, verifier, nil
}

// getPubShare creates PubShare corresponding to a secret share with given Verifiers.
// This function has been taken from:
// https://github.com/coinbase/kryptology/blob/71ffd4cbf01951cd0ee056fc7b45b13ffb178330/pkg/sharing/v1/feldman.go#L66
// where Verifiers(coefficients of public polynomial) are used to compute sum of products of public polynomial with
// identifier as x coordinate.
func getPubShare(identifier uint32, verifier *share.FeldmanVerifier) (*PubShare, error) {
	curve := curves.GetCurveByName(verifier.Commitments[0].CurveName())
	if curve != curves.BLS12381G1() {
		return nil, errors.New("curve mismatch")
	}

	x := curve.Scalar.New(int(identifier))
	i := curve.Scalar.One()

	// c_0
	pubshare := verifier.Commitments[0]

	// Compute the sum of products
	// c_0 + c_1 * i + c_2 * {i^2} + c_3 * {i^3} ... c_t * {i_t}
	for j := 1; j < len(verifier.Commitments); j++ {
		// i *= x
		i = i.Mul(x)

		// c_i * i
		c := verifier.Commitments[j].Mul(i)

		// ... + c_j^{i^j}
		pubshare = pubshare.Add(c)
	}

	g1Point, err := keyGroup.FromUncompressed(pubshare.ToAffineUncompressed())
	if err != nil {
		return nil, err
	}

	pks := &bls_sig.PublicKey{}
	err = pks.UnmarshalBinary(keyGroup.ToCompressed(g1Point))
	if err != nil {
		return nil, err
	}

	return &PubShare{identifier: uint8(identifier), Value: pks}, nil
}
