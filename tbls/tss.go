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

package tbls

import (
	"io"

	"github.com/coinbase/kryptology/pkg/core/curves"
	share "github.com/coinbase/kryptology/pkg/sharing"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
)

// blsScheme is the BLS12-381 ETH2 signature scheme with standard domain separation tag used for signatures.
// blsScheme uses proofs of possession to mitigate rogue-key attacks.
// see: https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-03#section-4.2.3
var blsScheme = bls_sig.NewSigEth2()

// Scheme returns the BLS12-381 ETH2 signature scheme.
func Scheme() *bls_sig.SigEth2 {
	return blsScheme
}

// Keygen returns a new BLS key pair.
func Keygen() (*bls_sig.PublicKey, *bls_sig.SecretKey, error) {
	pubkey, secret, err := blsScheme.Keygen()
	if err != nil {
		return nil, nil, errors.Wrap(err, "generate key")
	}

	return pubkey, secret, nil
}

// KeygenWithSeed returns a new BLS key pair seeded from the reader.
func KeygenWithSeed(reader io.Reader) (*bls_sig.PublicKey, *bls_sig.SecretKey, error) {
	ikm := make([]byte, 32)
	_, _ = reader.Read(ikm)
	pubkey, secret, err := blsScheme.KeygenWithSeed(ikm)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generate key")
	}

	return pubkey, secret, nil
}

// TSS (threshold signing scheme) wraps PubKey (PublicKey), Pubshares (the public shares corresponding to each secret key share)
// and threshold (number of shares).
type TSS struct {
	pubshares map[int]*bls_sig.PublicKey
	numShares int
	threshold int

	// publicKey inferred from verifier commitments in NewTSS.
	publicKey *bls_sig.PublicKey
}

// NumShares returns the number of shares in the threshold signature scheme.
func (t TSS) NumShares() int {
	return t.numShares
}

// PublicKey returns the threshold signature scheme's root public key.
func (t TSS) PublicKey() *bls_sig.PublicKey {
	return t.publicKey
}

// Threshold returns the minimum number of partial signatures required to aggregate the threshold signature.
func (t TSS) Threshold() int {
	return t.threshold
}

// PublicShare returns a share's public key by share index (identifier).
func (t TSS) PublicShare(shareIdx int) *bls_sig.PublicKey {
	return t.pubshares[shareIdx]
}

func (t TSS) PublicShares() map[int]*bls_sig.PublicKey {
	return t.pubshares
}

func NewTSS(verifier *share.FeldmanVerifier, numShares int) (TSS, error) {
	pk := new(bls_sig.PublicKey)
	err := pk.UnmarshalBinary(verifier.Commitments[0].ToAffineCompressed())
	if err != nil {
		return TSS{}, errors.Wrap(err, "unmarshal pubkey")
	}

	pubshares := make(map[int]*bls_sig.PublicKey)
	for i := 1; i <= numShares; i++ {
		pubshares[i], err = getPubShare(i, verifier)
		if err != nil {
			return TSS{}, err
		}
	}

	return TSS{
		pubshares: pubshares,
		publicKey: pk,
		numShares: numShares,
		threshold: len(verifier.Commitments),
	}, nil
}

// GenerateTSS returns a new random instance of threshold signing scheme and associated SecretKeyShares.
// It generates n number of secret key shares where t of them can be combined to sign a message.
func GenerateTSS(t, n int, reader io.Reader) (TSS, []*bls_sig.SecretKeyShare, error) {
	ikm := make([]byte, 32)
	_, _ = reader.Read(ikm)
	_, secret, err := blsScheme.KeygenWithSeed(ikm)
	if err != nil {
		return TSS{}, nil, errors.Wrap(err, "bls key generation")
	}

	sks, verifier, err := SplitSecret(secret, t, n, reader)
	if err != nil {
		return TSS{}, nil, errors.Wrap(err, "generate secret shares")
	}

	tss, err := NewTSS(verifier, n)
	if err != nil {
		return TSS{}, nil, err
	}

	return tss, sks, nil
}

// Aggregate returns an aggregated signature.
func Aggregate(partialSigs []*bls_sig.PartialSignature) (*bls_sig.Signature, error) {
	aggSig, err := blsScheme.CombineSignatures(partialSigs...)
	if err != nil {
		return nil, errors.Wrap(err, "aggregate signatures")
	}

	return aggSig, nil
}

// VerifyAndAggregate verifies all partial signatures against a message and aggregates them.
// It returns the aggregated signature and slice of valid partial signature identifiers.
func VerifyAndAggregate(tss TSS, partialSigs []*bls_sig.PartialSignature, msg []byte) (*bls_sig.Signature, []byte, error) {
	if len(partialSigs) < tss.Threshold() {
		return nil, nil, errors.New("insufficient signatures")
	}

	var (
		signers   []byte
		validSigs []*bls_sig.PartialSignature
	)

	for _, psig := range partialSigs {
		// TODO(dhruv): add break condition if valid shares >= threshold
		pubShare := tss.PublicShare(int(psig.Identifier))

		sig := &bls_sig.Signature{Value: psig.Signature}
		ok, err := blsScheme.Verify(pubShare, msg, sig)
		if err != nil || !ok {
			continue
		}

		validSigs = append(validSigs, psig)
		signers = append(signers, psig.Identifier)
	}

	if len(validSigs) < tss.Threshold() {
		return nil, nil, errors.New("insufficient valid signatures")
	}

	aggSig, err := blsScheme.CombineSignatures(validSigs...)
	if err != nil {
		return nil, nil, errors.Wrap(err, "aggregate signatures")
	}

	return aggSig, signers, nil
}

// Verify verifies the given signature(sig) on message(msg) with given public key (pk).
func Verify(pk *bls_sig.PublicKey, msg []byte, sig *bls_sig.Signature) (bool, error) {
	res, err := blsScheme.Verify(pk, msg, sig)
	if err != nil {
		return res, errors.Wrap(err, "verify signature")
	}

	return res, nil
}

// PartialSign signs given message(msg) using given Secret Key Share(sks) and returns a Partial Signature.
func PartialSign(sks *bls_sig.SecretKeyShare, msg []byte) (*bls_sig.PartialSignature, error) {
	psig, err := blsScheme.PartialSign(sks, msg)
	if err != nil {
		return nil, errors.Wrap(err, "partial sign")
	}

	return psig, nil
}

// Sign signs given message(msg) using given Secret Key(sk) and returns a Signature.
func Sign(sk *bls_sig.SecretKey, msg []byte) (*bls_sig.Signature, error) {
	sig, err := blsScheme.Sign(sk, msg)
	if err != nil {
		return nil, errors.Wrap(err, "sign")
	}

	return sig, nil
}

// CombineShares returns the root/group secret by combining threshold secret shares.
func CombineShares(shares []*bls_sig.SecretKeyShare, t, n int) (*bls_sig.SecretKey, error) {
	var shamirShares []*share.ShamirShare
	for _, s := range shares {
		b, err := s.MarshalBinary()
		if err != nil {
			return nil, errors.Wrap(err, "marshal key share")
		}

		lenMin1 := len(b) - 1
		shamirShare := share.ShamirShare{
			Id:    uint32(b[lenMin1]),
			Value: b[:lenMin1],
		}

		shamirShares = append(shamirShares, &shamirShare)
	}

	scheme, err := share.NewFeldman(uint32(t), uint32(n), curves.BLS12381G1())
	if err != nil {
		return nil, errors.Wrap(err, "new Feldman VSS")
	}

	secretScaler, err := scheme.Combine(shamirShares...)
	if err != nil {
		return nil, errors.Wrap(err, "combine shares")
	}

	resp := new(bls_sig.SecretKey)
	if err := resp.UnmarshalBinary(secretScaler.Bytes()); err != nil {
		return nil, errors.Wrap(err, "unmarshal secret")
	}

	return resp, nil
}

// SplitSecret splits the secret and returns n secret shares and t verifiers.
func SplitSecret(secret *bls_sig.SecretKey, t, n int, reader io.Reader) ([]*bls_sig.SecretKeyShare, *share.FeldmanVerifier, error) {
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

// getPubShare returns the public key share for the i'th/identifier/shareIdx share from the verifier commitments.
func getPubShare(identifier int, verifier *share.FeldmanVerifier) (*bls_sig.PublicKey, error) {
	curve := curves.GetCurveByName(verifier.Commitments[0].CurveName())
	if curve != curves.BLS12381G1() {
		return nil, errors.New("curve mismatch")
	}

	x := curve.Scalar.New(identifier)
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

	pk := new(bls_sig.PublicKey)
	err := pk.UnmarshalBinary(pubshare.ToAffineCompressed())
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal pubshare")
	}

	return pk, nil
}
