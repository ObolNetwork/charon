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

package tblsconv

import (
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	v2 "github.com/obolnetwork/charon/tbls/v2"
)

// SigFromCore converts a core workflow Signature type into a tbls.Signature.
func SigFromCore(sig core.Signature) (v2.Signature, error) {
	return SignatureFromBytes(sig)
}

// SigToCore converts a tbls.Signature into a core workflow Signature type.
func SigToCore(sig v2.Signature) core.Signature {
	return sig[:]
}

// SigFromBytes converts arbitrary bytes to a v2.Signature.
func SigFromBytes(sig []byte) (v2.Signature, error) {
	if len(sig) != len(v2.Signature{}) {
		return v2.Signature{}, errors.New("data is not of the correct length")
	}

	return *(*v2.Signature)(sig), nil
}

// SigToETH2 converts a tbls.Signature into an eth2 phase0 bls signature.
func SigToETH2(sig v2.Signature) eth2p0.BLSSignature {
	return eth2p0.BLSSignature(sig)
}

func PubkeyToETH2(pk v2.PublicKey) (eth2p0.BLSPubKey, error) {
	return eth2p0.BLSPubKey(pk), nil
}

// PrivkeyFromBytes returns a v2.PrivateKey from the given compressed private key bytes contained in data.
// Returns an error if the data isn't of the expected length.
func PrivkeyFromBytes(data []byte) (v2.PrivateKey, error) {
	if len(data) != len(v2.PrivateKey{}) {
		return v2.PrivateKey{}, errors.New("data is not of the correct length")
	}

	return *(*v2.PrivateKey)(data), nil
}

// PubkeyFromBytes returns a v2.PublicKey from the given compressed public key bytes contained in data.
// Returns an error if the data isn't of the expected length.
func PubkeyFromBytes(data []byte) (v2.PublicKey, error) {
	if len(data) != len(v2.PublicKey{}) {
		return v2.PublicKey{}, errors.New("data is not of the correct length")
	}

	return *(*v2.PublicKey)(data), nil
}

// SignatureFromBytes returns a v2.Signature from the given compressed signature bytes contained in data.
// Returns an error if the data isn't of the expected length.
func SignatureFromBytes(data []byte) (v2.Signature, error) {
	if len(data) != len(v2.Signature{}) {
		return v2.Signature{}, errors.New("data is not of the correct length")
	}

	return *(*v2.Signature)(data), nil
}
