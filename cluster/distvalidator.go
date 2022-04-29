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

package cluster

import ssz "github.com/ferranbt/fastssz"

// DistValidator is a distributed validator (1x32ETH) managed by the cluster.
type DistValidator struct {
	// PubKey is the root distributed public key.
	PubKey string `json:"distributed_public_key"`

	// Verifiers are the public shares.
	Verifiers [][]byte `json:"threshold_verifiers"`

	// FeeRecipientAddress Ethereum address override for this validator, defaults to definition withdrawal address.
	FeeRecipientAddress string `json:"fee_recipient_address,omitempty"`
}

// HashTreeRoot ssz hashes the Lock object.
func (v DistValidator) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(v) //nolint:wrapcheck
}

// HashTreeRootWith ssz hashes the Lock object with a hasher.
func (v DistValidator) HashTreeRootWith(hh *ssz.Hasher) error {
	indx := hh.Index()

	// Field (0) 'PubKey'
	hh.PutBytes([]byte(v.PubKey))

	for _, verifier := range v.Verifiers {
		// Field (1+i) 'Verifier'
		hh.PutBytes(verifier)
	}

	// Field (N) 'FeeRecipientAddress'
	hh.PutBytes([]byte(v.FeeRecipientAddress))

	hh.Merkleize(indx)

	return nil
}
