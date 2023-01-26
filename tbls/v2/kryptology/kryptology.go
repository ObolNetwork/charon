package kryptology

import (
	"crypto/rand"

	"github.com/coinbase/kryptology/pkg/core/curves"
	share "github.com/coinbase/kryptology/pkg/sharing"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/obolnetwork/charon/app/errors"
	v2 "github.com/obolnetwork/charon/tbls/v2"
)

// blsScheme is the BLS12-381 ETH2 signature scheme with standard domain separation tag used for signatures.
// blsScheme uses proofs of possession to mitigate rogue-key attacks.
// see: https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-03#section-4.2.3
var blsScheme = bls_sig.NewSigEth2()

// Kryptology is an Implementation with Kryptology-specific inner logic.
type Kryptology struct{}

func (Kryptology) GenerateSecretKey() (v2.PrivateKey, error) {
	_, secret, err := blsScheme.Keygen()
	if err != nil {
		return v2.PrivateKey{}, errors.Wrap(err, "generate key")
	}

	ret, err := secret.MarshalBinary()
	if err != nil {
		return v2.PrivateKey{}, errors.Wrap(err, "cannot unmarshal generated secret into kryptology object")
	}

	// Commenting here once, this syntax will appear often:
	// here I'm converting ret to a pointer to instance of v2.PrivateKey, which is
	// an array with constant size.
	// I'm dereferencing it to return a copy as well.
	// Ref: https://go.dev/ref/spec#Conversions_from_slice_to_array_pointer
	return *(*v2.PrivateKey)(ret), nil
}

func (Kryptology) SecretToPublicKey(key v2.PrivateKey) (v2.PublicKey, error) {
	rawKey := new(bls_sig.SecretKey)
	if err := rawKey.UnmarshalBinary(key[:]); err != nil {
		return v2.PublicKey{}, errors.Wrap(err, "unmarshal raw key into kryptology object")
	}

	pubKey, err := rawKey.GetPublicKey()
	if err != nil {
		return v2.PublicKey{}, errors.Wrap(err, "get public key")
	}

	ret, err := pubKey.MarshalBinary()
	if err != nil {
		return v2.PublicKey{}, errors.Wrap(err, "cannot marshal public key from kryptology object")
	}

	return *(*v2.PublicKey)(ret), nil
}

func (Kryptology) ThresholdSplit(secret v2.PrivateKey, total uint, threshold uint) (map[int]v2.PrivateKey, error) {
	scheme, err := share.NewFeldman(uint32(threshold), uint32(total), curves.BLS12381G1())
	if err != nil {
		return nil, errors.Wrap(err, "new Feldman VSS")
	}

	secretScaler, err := curves.BLS12381G1().NewScalar().SetBytes(secret[:])
	if err != nil {
		return nil, errors.Wrap(err, "convert to scaler")
	}

	_, shares, err := scheme.Split(secretScaler, rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "split Secret Key")
	}

	sks := make(map[int]v2.PrivateKey)

	for _, s := range shares {
		sks[int(s.Id)] = *(*v2.PrivateKey)(s.Value)
	}

	return sks, nil
}

func (Kryptology) RecoverSecret(shares map[int]v2.PrivateKey, total uint, threshold uint) (v2.PrivateKey, error) {
	var shamirShares []*share.ShamirShare
	for idx, value := range shares {
		// do a local copy, we're dealing with references here
		value := value
		shamirShare := share.ShamirShare{
			Id:    uint32(idx),
			Value: value[:],
		}

		shamirShares = append(shamirShares, &shamirShare)
	}

	scheme, err := share.NewFeldman(uint32(threshold), uint32(total), curves.BLS12381G1())
	if err != nil {
		return v2.PrivateKey{}, errors.Wrap(err, "new Feldman VSS")
	}

	secretScaler, err := scheme.Combine(shamirShares...)
	if err != nil {
		return v2.PrivateKey{}, errors.Wrap(err, "combine shares")
	}

	resp := new(bls_sig.SecretKey)
	if err := resp.UnmarshalBinary(secretScaler.Bytes()); err != nil {
		return v2.PrivateKey{}, errors.Wrap(err, "unmarshal secret")
	}

	ret, err := resp.MarshalBinary()
	if err != nil {
		return v2.PrivateKey{}, errors.Wrap(err, "cannot marshal private key from kryptology object")
	}

	return *(*v2.PrivateKey)(ret), nil
}

func (Kryptology) ThresholdAggregate(partialSignaturesByIndex map[int]v2.Signature) (v2.Signature, error) {
	var kryptologyPartialSigs []*bls_sig.PartialSignature

	for idx, sig := range partialSignaturesByIndex {
		// do a local copy, we're dealing with references here
		sig := sig
		rawSign := new(bls_sig.Signature)
		if err := rawSign.UnmarshalBinary(sig[:]); err != nil {
			return v2.Signature{}, errors.Wrap(err, "unmarshal raw signature into kryptology object")
		}

		kryptologyPartialSigs = append(kryptologyPartialSigs, &bls_sig.PartialSignature{
			Identifier: byte(idx),
			Signature:  rawSign.Value,
		})
	}

	aggSig, err := blsScheme.CombineSignatures(kryptologyPartialSigs...)
	if err != nil {
		return v2.Signature{}, errors.Wrap(err, "aggregate signatures")
	}

	ret, err := aggSig.MarshalBinary()
	if err != nil {
		return v2.Signature{}, errors.Wrap(err, "cannot marshal signature from kryptology object")
	}

	return *(*v2.Signature)(ret), nil
}

func (Kryptology) Verify(compressedPublicKey v2.PublicKey, data []byte, signature v2.Signature) error {
	rawKey := new(bls_sig.PublicKey)
	if err := rawKey.UnmarshalBinary(compressedPublicKey[:]); err != nil {
		return errors.Wrap(err, "unmarshal raw public key into kryptology object")
	}

	rawSign := new(bls_sig.Signature)
	if err := rawSign.UnmarshalBinary(signature[:]); err != nil {
		return errors.Wrap(err, "unmarshal raw signature into kryptology object")
	}

	valid, err := blsScheme.Verify(rawKey, data, rawSign)
	if err != nil {
		return errors.Wrap(err, "verification error")
	}

	if !valid {
		return errors.New("signature verification failed")
	}

	return nil
}

func (Kryptology) Sign(privateKey v2.PrivateKey, data []byte) (v2.Signature, error) {
	rawKey := new(bls_sig.SecretKey)
	if err := rawKey.UnmarshalBinary(privateKey[:]); err != nil {
		return v2.Signature{}, errors.Wrap(err, "unmarshal raw private key into kryptology object")
	}

	rawSign, err := blsScheme.Sign(rawKey, data)
	if err != nil {
		return v2.Signature{}, errors.Wrap(err, "cannot execute kryptology signature")
	}

	ret, err := rawSign.MarshalBinary()
	if err != nil {
		return v2.Signature{}, errors.Wrap(err, "cannot marshal signature from kryptology object")
	}

	return *(*v2.Signature)(ret), nil
}
