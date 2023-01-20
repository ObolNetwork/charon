package taketwo

import "sync"

var impl Implementation = Unimplemented{}
var implLock sync.Mutex

// Implementation defines the backing implementation for all the public functions of this package.
type Implementation interface {
	// GenerateSecretKey generates a secret key and returns its compressed serialized representation.
	GenerateSecretKey() ([]byte, error)

	// SecretToPublicKey extracts the public key associated with the secret passed in input, and returns its
	// compressed serialized representation.
	SecretToPublicKey([]byte) ([]byte, error)

	// ThresholdSplit splits secret into total units of secret keys, with the given threshold.
	// It returns a map that associates each private, compressed private key to its ID.
	ThresholdSplit(secret []byte, total uint, threshold uint) (map[int][]byte, error)

	// RecoverSecret recovers the original secret off the input shares.
	RecoverSecret(shares map[int][]byte) ([]byte, error)

	// ThresholdAggregate aggregates the partial signatures passed in input in the final original signature.
	ThresholdAggregate(partialSignaturesByIndex map[int][]byte) ([]byte, error)

	// Verify verifies that signature has been produced with the private key associated with compressedPublicKey, on
	// the provided data.
	Verify(compressedPublicKey []byte, data []byte, signature []byte) error

	// Sign signs data with the provided private key, and returns the resulting signature.
	// This function works on both shares of private keys, and complete private keys.
	Sign(privateKey []byte, data []byte) ([]byte, error)
}

// SetImplementation sets newImpl as the package backing implementation.
func SetImplementation(newImpl Implementation) {
	implLock.Lock()
	defer implLock.Unlock()
	impl = newImpl
}

func GenerateSecretKey() ([]byte, error) {
	return impl.GenerateSecretKey()
}

func SecretToPublicKey(secret []byte) ([]byte, error) {
	return impl.SecretToPublicKey(secret)
}

func ThrehsoldSplit(secret []byte, total uint, threshold uint) (map[int][]byte, error) {
	return impl.ThresholdSplit(secret, total, threshold)
}

func RecoverSecret(shares map[int][]byte) ([]byte, error) {
	return impl.RecoverSecret(shares)
}

func ThresholdAggregate(partialSignaturesByIndex map[int][]byte) ([]byte, error) {
	return impl.ThresholdAggregate(partialSignaturesByIndex)
}

func Verify(compressedPublicKey []byte, data []byte, signature []byte) error {
	return impl.Verify(compressedPublicKey, data, signature)
}

func Sign(privateKey []byte, data []byte) ([]byte, error) {
	return impl.Sign(privateKey, data)
}
