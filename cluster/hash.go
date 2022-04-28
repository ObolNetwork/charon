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

// HashTreeRoot ssz hashes the Params object.
func (s Params) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(s) //nolint:wrapcheck
}

// HashTreeRootWith ssz hashes the Params object with a hasher.
func (s Params) HashTreeRootWith(hh *ssz.Hasher) error {
	indx := hh.Index()

	// Field (0) 'UUID'
	hh.PutBytes([]byte(s.UUID))

	// Field (1) 'Name'
	hh.PutBytes([]byte(s.Name))

	// Field (2) 'Version'
	hh.PutBytes([]byte(s.Version))

	// Field (3) 'NumValidators'
	hh.PutUint64(uint64(s.NumValidators))

	// Field (4) 'Threshold'
	hh.PutUint64(uint64(s.Threshold))

	// Field (5) 'FeeRecipientAddress'
	hh.PutBytes([]byte(s.FeeRecipientAddress))

	// Field (6) 'WithdrawalAddress'
	hh.PutBytes([]byte(s.WithdrawalAddress))

	// Field (7) 'DKGAlgorithm'
	hh.PutBytes([]byte(s.DKGAlgorithm))

	// Field (8) 'ForkVersion'
	hh.PutBytes([]byte(s.ForkVersion))

	for _, operator := range s.Operators {
		// Field (9+i) 'Target'
		if err := operator.HashTreeRootWith(hh); err != nil {
			return err
		}
	}

	hh.Merkleize(indx)

	return nil
}

// HashTreeRoot ssz hashes the Params object.
func (o Operator) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(o) //nolint:wrapcheck
}

// HashTreeRootWith ssz hashes the Operator object with a hasher.
func (o Operator) HashTreeRootWith(hh *ssz.Hasher) error {
	indx := hh.Index()

	// Field (0) 'Address'
	hh.PutBytes([]byte(o.Address))

	// Field (1) 'ENR'
	hh.PutBytes([]byte(o.ENR))

	// Field (2) 'Nonce'
	hh.PutUint64(uint64(o.Nonce))

	// Field (3) 'Signature'
	hh.PutBytes(o.Signature)

	hh.Merkleize(indx)

	return nil
}

// HashTreeRoot ssz hashes the Lock object.
func (l Lock) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(l) //nolint:wrapcheck
}

// HashTreeRootWith ssz hashes the Lock object with a hasher.
func (l Lock) HashTreeRootWith(hh *ssz.Hasher) error {
	indx := hh.Index()

	// Field (0) 'Params'
	if err := l.Params.HashTreeRootWith(hh); err != nil {
		return err
	}

	for _, validator := range l.Validators {
		// Field (1+i) 'Validator'
		if err := validator.HashTreeRootWith(hh); err != nil {
			return err
		}
	}

	hh.Merkleize(indx)

	return nil
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
