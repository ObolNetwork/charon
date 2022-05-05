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

// Package tblsconv provides functions to convert into and from kryptology bls_sig types.
// This package is inspired by strconv.
package tblsconv

import (
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/core/curves/native/bls12381"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
)

// KeyFromBytes unmarshalls the bytes into a kryptology bls public key.
func KeyFromBytes(bytes []byte) (*bls_sig.PublicKey, error) {
	resp := new(bls_sig.PublicKey)
	if err := resp.UnmarshalBinary(bytes); err != nil {
		return nil, errors.Wrap(err, "unmarshal pubkey")
	}

	return resp, nil
}

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
	point, err := new(bls12381.G2).FromCompressed((*[96]byte)(sig[:]))
	if err != nil {
		return nil, errors.Wrap(err, "uncompress sig")
	}

	return &bls_sig.Signature{Value: *point}, nil
}

func SigFromPartial(psig *bls_sig.PartialSignature) *bls_sig.Signature {
	return &bls_sig.Signature{Value: psig.Signature}
}

// SigToETH2 converts a kryptology bls signature into an eth2 phase0 bls signature.
func SigToETH2(sig *bls_sig.Signature) eth2p0.BLSSignature {
	return sig.Value.ToCompressed()
}

// SigToCore converts a kryptology bls signature into a core workflow Signature type.
func SigToCore(sig *bls_sig.Signature) core.Signature {
	s := sig.Value.ToCompressed()
	return core.SigFromETH2(s)
}

// SigFromCore converts a core workflow Signature type into a kryptology bls signature.
func SigFromCore(sig core.Signature) (*bls_sig.Signature, error) {
	point, err := new(bls12381.G2).FromCompressed((*[96]byte)(sig))
	if err != nil {
		return nil, errors.Wrap(err, "uncompress sig")
	}

	return &bls_sig.Signature{Value: *point}, nil
}

// ShareToSecret converts a bls secret share into a normal bls secret.
func ShareToSecret(share *bls_sig.SecretKeyShare) (*bls_sig.SecretKey, error) {
	b, err := share.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "marshal share")
	}

	// shamir.SecretShare.Bytes() strips leading zeros...
	const sksLen = 33
	if len(b) < sksLen {
		b = append(make([]byte, sksLen-len(b)), b...)
	}

	resp := new(bls_sig.SecretKey)
	if err := resp.UnmarshalBinary(b[:len(b)-1]); err != nil {
		return nil, errors.Wrap(err, "unmarshal secret")
	}

	return resp, nil
}

// SecretFromBytes returns a bls secret from bytes.
func SecretFromBytes(secret []byte) (*bls_sig.SecretKey, error) {
	resp := new(bls_sig.SecretKey)
	if err := resp.UnmarshalBinary(secret); err != nil {
		return nil, errors.Wrap(err, "unmarshal secret")
	}

	return resp, nil
}

// SecretToBytes converts a bls secret into bytes.
func SecretToBytes(secret *bls_sig.SecretKey) ([]byte, error) {
	resp, err := secret.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "marshal secret")
	}

	return resp, nil
}
