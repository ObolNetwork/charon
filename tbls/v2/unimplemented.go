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

package v2

import (
	"github.com/obolnetwork/charon/app/errors"
)

var ErrNotImplemented = errors.New("not implemented")

// Unimplemented is an Implementation that always returns ErrNotImplemented.
type Unimplemented struct{}

func (Unimplemented) GenerateSecretKey() (PrivateKey, error) {
	return PrivateKey{}, ErrNotImplemented
}

func (Unimplemented) SecretToPublicKey(_ PrivateKey) (PublicKey, error) {
	return PublicKey{}, ErrNotImplemented
}

func (Unimplemented) ThresholdSplit(_ PrivateKey, _ uint, _ uint) (map[int]PrivateKey, error) {
	return nil, ErrNotImplemented
}

func (Unimplemented) RecoverSecret(_ map[int]PrivateKey, _ uint, _ uint) (PrivateKey, error) {
	return PrivateKey{}, ErrNotImplemented
}

func (Unimplemented) ThresholdAggregate(_ map[int]Signature) (Signature, error) {
	return Signature{}, ErrNotImplemented
}

func (Unimplemented) Verify(_ PublicKey, _ []byte, _ Signature) error {
	return ErrNotImplemented
}

func (Unimplemented) Sign(_ PrivateKey, _ []byte) (Signature, error) {
	return Signature{}, ErrNotImplemented
}

func (Unimplemented) VerifyAggregate(_ []PublicKey, _ Signature, _ []byte) error {
	return ErrNotImplemented
}

func (Unimplemented) Aggregate(_ []Signature) (Signature, error) {
	return Signature{}, ErrNotImplemented
}

func (Unimplemented) AggregatePublicKeys(_ []PublicKey) (PublicKey, error) {
	return PublicKey{}, ErrNotImplemented
}
