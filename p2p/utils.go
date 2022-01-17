package p2p

import (
	"crypto/ecdsa"
	gcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/libp2p/go-libp2p-core/crypto"
)

func convertInterfaceToPrivKey(privkey crypto.PrivKey) *ecdsa.PrivateKey {
	typeAssertedKey := (*ecdsa.PrivateKey)(privkey.(*crypto.Secp256k1PrivateKey))
	typeAssertedKey.Curve = gcrypto.S256() // Temporary hack, so libp2p Secp256k1 is recognized as geth Secp256k1 in disc v5.1.
	return typeAssertedKey
}
