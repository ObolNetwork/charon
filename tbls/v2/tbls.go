package v2

import "sync"

var impl Implementation = Unimplemented{}
var implLock sync.Mutex

type (
	// PublicKey is a byte slice containing a compressed BLS12-381 public key.
	PublicKey []byte

	// PrivateKey is a byte slice containing a compressed BLS12-381 private key.
	PrivateKey []byte

	// Signature is a byte slice containing a BLS12-381 signature.
	Signature []byte
)

// Implementation defines the backing implementation for all the public functions of this package.
type Implementation interface {
	// GenerateSecretKey generates a secret key and returns its compressed serialized representation.
	GenerateSecretKey() (PrivateKey, error)

	// SecretToPublicKey extracts the public key associated with the secret passed in input, and returns its
	// compressed serialized representation.
	SecretToPublicKey(PrivateKey) (PublicKey, error)

	// ThresholdSplit splits a compressed secret into total units of secret keys, with the given threshold.
	// It returns a map that associates each private, compressed private key to its ID.
	ThresholdSplit(secret PrivateKey, total uint, threshold uint) (map[int]PrivateKey, error)

	// RecoverSecret recovers the original secret off the input shares.
	RecoverSecret(shares map[int]PrivateKey, total uint, threshold uint) (PrivateKey, error)

	// ThresholdAggregate aggregates the partial signatures passed in input in the final original signature.
	ThresholdAggregate(partialSignaturesByIndex map[int]Signature) (Signature, error)

	// Verify verifies that signature has been produced with the private key associated with compressedPublicKey, on
	// the provided data.
	Verify(compressedPublicKey PublicKey, data []byte, signature Signature) error

	// Sign signs data with the provided private key, and returns the resulting signature.
	// This function works on both shares of private keys, and complete private keys.
	Sign(privateKey PrivateKey, data []byte) (Signature, error)
}

// SetImplementation sets newImpl as the package backing implementation.
func SetImplementation(newImpl Implementation) {
	implLock.Lock()
	defer implLock.Unlock()
	impl = newImpl
}

func GenerateSecretKey() (PrivateKey, error) {
	return impl.GenerateSecretKey()
}

func SecretToPublicKey(secret PrivateKey) (PublicKey, error) {
	return impl.SecretToPublicKey(secret)
}

func ThresholdSplit(secret PrivateKey, total uint, threshold uint) (map[int]PrivateKey, error) {
	return impl.ThresholdSplit(secret, total, threshold)
}

func RecoverSecret(shares map[int]PrivateKey, total uint, threshold uint) (PrivateKey, error) {
	return impl.RecoverSecret(shares, total, threshold)
}

func ThresholdAggregate(partialSignaturesByIndex map[int]Signature) (Signature, error) {
	return impl.ThresholdAggregate(partialSignaturesByIndex)
}

func Verify(compressedPublicKey PublicKey, data []byte, signature Signature) error {
	return impl.Verify(compressedPublicKey, data, signature)
}

func Sign(privateKey PrivateKey, data []byte) (Signature, error) {
	return impl.Sign(privateKey, data)
}
