package taketwo

import "fmt"

var ErrNotImplemented = fmt.Errorf("not implemented")

// Unimplemented is an Implementation that always returns ErrNotImplemented.
type Unimplemented struct{}

func (u Unimplemented) GenerateSecretKey() (PrivateKey, error) {
	return nil, ErrNotImplemented
}

func (u Unimplemented) SecretToPublicKey(_ PrivateKey) (PublicKey, error) {
	return nil, ErrNotImplemented
}

func (u Unimplemented) ThresholdSplit(_ PrivateKey, _ uint, _ uint) (map[int]PrivateKey, error) {
	return nil, ErrNotImplemented
}

func (u Unimplemented) RecoverSecret(_ map[int]PrivateKey) (PrivateKey, error) {
	return nil, ErrNotImplemented
}

func (u Unimplemented) ThresholdAggregate(_ map[int]Signature) (Signature, error) {
	return nil, ErrNotImplemented
}

func (u Unimplemented) Verify(_ PublicKey, _ []byte, _ Signature) error {
	return ErrNotImplemented
}

func (u Unimplemented) Sign(_ PrivateKey, _ []byte) (Signature, error) {
	return nil, ErrNotImplemented
}
