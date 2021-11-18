package crypto

import (
	"encoding/hex"
	"fmt"

	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
)

// BLSPointToHex returns the hex serialization of a BLS public key (G1) or signature (G2).
func BLSPointToHex(p kyber.Point) string {
	b, _ := p.MarshalBinary()
	return hex.EncodeToString(b)
}

func BLSPointFromHex(hexStr string) (kyber.Point, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	var p kyber.Point
	switch len(b) {
	case 48:
		p = bls.NullKyberG1()
	case 96:
		p = bls.NullKyberG2()
	default:
		return nil, fmt.Errorf("weird length: %d", len(b))
	}
	if p.MarshalSize() != len(b) {
		panic(fmt.Sprintf("expected %T to be %d bytes, actually is %d", p, len(b), p.MarshalSize()))
	}
	if err := p.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return p, nil
}
