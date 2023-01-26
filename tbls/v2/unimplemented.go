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
