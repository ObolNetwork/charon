package crypto

import (
	"fmt"

	"github.com/drand/kyber/share"
	"github.com/google/uuid"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
)

// Keystore describes the EIP-2335 BLS12-381 keystore file format.
//
// https://eips.ethereum.org/EIPS/eip-2335
type Keystore struct {
	Crypto      map[string]interface{} `json:"crypto"`      // checksum, cipher, kdf
	Description string                 `json:"description"` // free-form text string explaining keystore purpose
	UUID        string                 `json:"uuid"`        // random UUID
	Pubkey      string                 `json:"pubkey"`      // BLS12-381 hex public key
	Path        string                 `json:"path"`        // EIP-2334 derivation path if hierarchical deriv, otherwise empty
	Version     uint                   `json:"version"`     // must be 4
}

// TBLSShareToKeystore constructs a new keystore from a threshold BLS private key share.
func TBLSShareToKeystore(scheme *TBLSScheme, priPoly *share.PriShare, password string) (*Keystore, error) {
	pubkeyHex := BLSPointToHex(scheme.PubPoly.Commit())
	pubShare := BLSKeyGroup.Point().Mul(priPoly.V, nil)
	pubShareHex := BLSPointToHex(pubShare)
	fmt.Printf("Share #%04d pubkey: %s\n", priPoly.I, pubShareHex)
	secret, err := priPoly.V.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key share: %w", err)
	}

	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	encryptor := keystorev4.New()
	cryptoFields, err := encryptor.Encrypt(secret, password)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key")
	}
	return &Keystore{
		Crypto: cryptoFields,
		Description: fmt.Sprintf("Obol Eth2 validator %s i=%d t=%d n=%d",
			pubkeyHex, priPoly.I, scheme.Threshold(), scheme.N),
		UUID:    id.String(),
		Pubkey:  pubShareHex,
		Path:    "",
		Version: encryptor.Version(),
	}, nil
}
