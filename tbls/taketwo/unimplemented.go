package taketwo

import "fmt"

var ErrNotImplemented = fmt.Errorf("not implemented")

// Unimplemented is an Implementation that always returns ErrNotImplemented.
type Unimplemented struct{}

func (u Unimplemented) GenerateSecretKey() ([]byte, error) {
	return nil, ErrNotImplemented
}

func (u Unimplemented) SecretToPublicKey(_ []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

func (u Unimplemented) ThresholdSplit(_ []byte, _ uint, _ uint) (map[int][]byte, error) {
	return nil, ErrNotImplemented
}

func (u Unimplemented) RecoverSecret(_ map[int][]byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

func (u Unimplemented) ThresholdAggregate(_ map[int][]byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

func (u Unimplemented) Verify(_ []byte, _ []byte, _ []byte) error {
	return ErrNotImplemented
}

func (u Unimplemented) Sign(_ []byte, _ []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}
