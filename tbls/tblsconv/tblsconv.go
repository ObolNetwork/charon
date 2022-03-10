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

// Package tblsconv provides functions to convert into and from kryptology bls_sig types.
// This package is inspired by strconv.
package tblsconv

import (
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	bls12381 "github.com/dB2510/kryptology/pkg/core/curves/native/bls12-381"
	"github.com/dB2510/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
)

// KeyFromETH2 converts an eth2 phase0 public key into a kryptology bls public key.
func KeyFromETH2(key eth2p0.BLSPubKey) (*bls_sig.PublicKey, error) {
	resp := new(bls_sig.PublicKey)
	if err := resp.UnmarshalBinary(key[:]); err != nil {
		return nil, errors.Wrap(err, "unmarshal pubkey")
	}

	return resp, nil
}

// KeyToETH2 converts a kryptology bls public key into an eth2 phase0 public key.
func KeyToETH2(key *bls_sig.PublicKey) (eth2p0.BLSPubKey, error) {
	b, err := key.MarshalBinary()
	if err != nil {
		return eth2p0.BLSPubKey{}, errors.Wrap(err, "marshal pubkey")
	}

	var resp eth2p0.BLSPubKey
	if n := copy(resp[:], b); n != len(resp) {
		return eth2p0.BLSPubKey{}, errors.Wrap(err, "invalid pubkey")
	}

	return resp, nil
}

// KeyFromCore converts a core workflow public key into a kryptology bls public key.
func KeyFromCore(key core.PubKey) (*bls_sig.PublicKey, error) {
	b, err := key.Bytes()
	if err != nil {
		return nil, err
	}

	pubkey := new(bls_sig.PublicKey)
	if err := pubkey.UnmarshalBinary(b); err != nil {
		return nil, errors.Wrap(err, "unmarshal pubkey")
	}

	return pubkey, nil
}

// KeyToCore converts a kryptology bls public key into a core workflow public key.
func KeyToCore(key *bls_sig.PublicKey) (core.PubKey, error) {
	b, err := key.MarshalBinary()
	if err != nil {
		return "", errors.Wrap(err, "marshal pubkey")
	}

	return core.PubKeyFromBytes(b)
}

// SigFromETH2 converts an eth2 phase0 bls signature into a kryptology bls signature.
func SigFromETH2(sig eth2p0.BLSSignature) (*bls_sig.Signature, error) {
	point, err := bls12381.NewG2().FromCompressed(sig[:])
	if err != nil {
		return nil, errors.Wrap(err, "uncompress sig")
	}

	return &bls_sig.Signature{Value: *point}, nil
}

func SigFromPartial(psig *bls_sig.PartialSignature) *bls_sig.Signature {
	return &bls_sig.Signature{Value: *psig.Signature}
}

// SigToETH2 converts a kryptology bls signature into an eth2 phase0 bls signature.
func SigToETH2(sig *bls_sig.Signature) eth2p0.BLSSignature {
	var resp eth2p0.BLSSignature
	copy(resp[:], bls12381.NewG2().ToCompressed(&sig.Value))

	return resp
}

// SigFromBytes converts bytes into a kryptology bls signature.
func SigFromBytes(sig []byte) (*bls_sig.Signature, error) {
	point, err := bls12381.NewG2().FromCompressed(sig)
	if err != nil {
		return nil, errors.Wrap(err, "uncompress sig")
	}

	return &bls_sig.Signature{Value: *point}, nil
}

// SigToBytes converts a kryptology bls signature to bytes.
func SigToBytes(sig *bls_sig.Signature) []byte {
	return bls12381.NewG2().ToCompressed(&sig.Value)
}

// ShareToSecret converts a bls secret share into a normal bls secret.
func ShareToSecret(share *bls_sig.SecretKeyShare) (*bls_sig.SecretKey, error) {
	b, err := share.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "marshal share")
	}

	resp := new(bls_sig.SecretKey)
	if err := resp.UnmarshalBinary(b[:len(b)-1]); err != nil {
		return nil, errors.Wrap(err, "unmarshal secret")
	}

	return resp, nil
}
