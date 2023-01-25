package kryptology

import (
	"crypto/rand"
	"github.com/coinbase/kryptology/pkg/core/curves"
	share "github.com/coinbase/kryptology/pkg/sharing"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/tbls/v2"
)

// blsScheme is the BLS12-381 ETH2 signature scheme with standard domain separation tag used for signatures.
// blsScheme uses proofs of possession to mitigate rogue-key attacks.
// see: https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-03#section-4.2.3
var blsScheme = bls_sig.NewSigEth2()

// Kryptology is an Implementation with Kryptology-specific inner logic.
type Kryptology struct{}

func (k Kryptology) GenerateSecretKey() (v2.PrivateKey, error) {
	_, secret, err := blsScheme.Keygen()
	if err != nil {
		return nil, errors.Wrap(err, "generate key")
	}

	return secret.MarshalBinary()
}

func (k Kryptology) SecretToPublicKey(key v2.PrivateKey) (v2.PublicKey, error) {
	rawKey := new(bls_sig.SecretKey)
	if err := rawKey.UnmarshalBinary(key); err != nil {
		return nil, errors.Wrap(err, "unmarshal raw key into kryptology object")
	}

	pubKey, err := rawKey.GetPublicKey()
	if err != nil {
		return nil, errors.Wrap(err, "get public key")
	}

	return pubKey.MarshalBinary()
}

func (k Kryptology) ThresholdSplit(secret v2.PrivateKey, total uint, threshold uint) (map[int]v2.PrivateKey, error) {
	scheme, err := share.NewFeldman(uint32(threshold), uint32(total), curves.BLS12381G1())
	if err != nil {
		return nil, errors.Wrap(err, "new Feldman VSS")
	}

	secretScaler, err := curves.BLS12381G1().NewScalar().SetBytes(secret)
	if err != nil {
		return nil, errors.Wrap(err, "convert to scaler")
	}

	_, shares, err := scheme.Split(secretScaler, rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "split Secret Key")
	}

	sks := make(map[int]v2.PrivateKey)

	for _, s := range shares {
		sks[int(s.Id)] = s.Value
	}

	return sks, nil
}

func (k Kryptology) RecoverSecret(shares map[int]v2.PrivateKey, total uint, threshold uint) (v2.PrivateKey, error) {
	var shamirShares []*share.ShamirShare
	for idx, value := range shares {
		shamirShare := share.ShamirShare{
			Id:    uint32(idx),
			Value: value,
		}

		shamirShares = append(shamirShares, &shamirShare)
	}

	scheme, err := share.NewFeldman(uint32(threshold), uint32(total), curves.BLS12381G1())
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

	return resp.MarshalBinary()
}

func (k Kryptology) ThresholdAggregate(partialSignaturesByIndex map[int]v2.Signature) (v2.Signature, error) {
	var kryptologyPartialSigs []*bls_sig.PartialSignature

	for idx, sig := range partialSignaturesByIndex {
		rawSign := new(bls_sig.Signature)
		if err := rawSign.UnmarshalBinary(sig); err != nil {
			return nil, errors.Wrap(err, "unmarshal raw signature into kryptology object")
		}

		kryptologyPartialSigs = append(kryptologyPartialSigs, &bls_sig.PartialSignature{
			Identifier: byte(idx),
			Signature:  rawSign.Value,
		})
	}

	aggSig, err := blsScheme.CombineSignatures(kryptologyPartialSigs...)
	if err != nil {
		return nil, errors.Wrap(err, "aggregate signatures")
	}

	return aggSig.MarshalBinary()
}

func (k Kryptology) Verify(compressedPublicKey v2.PublicKey, data []byte, signature v2.Signature) error {
	rawKey := new(bls_sig.PublicKey)
	if err := rawKey.UnmarshalBinary(compressedPublicKey); err != nil {
		return errors.Wrap(err, "unmarshal raw public key into kryptology object")
	}

	rawSign := new(bls_sig.Signature)
	if err := rawSign.UnmarshalBinary(signature); err != nil {
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

func (k Kryptology) Sign(privateKey v2.PrivateKey, data []byte) (v2.Signature, error) {
	rawKey := new(bls_sig.SecretKey)
	if err := rawKey.UnmarshalBinary(privateKey); err != nil {
		return nil, errors.Wrap(err, "unmarshal raw private key into kryptology object")
	}

	rawSign, err := blsScheme.Sign(rawKey, data)
	if err != nil {
		return nil, err
	}

	return rawSign.MarshalBinary()
}
