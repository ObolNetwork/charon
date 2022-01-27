// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

// BLSPointFromHex unwraps a hex serialization to a G1 or G2 point on the BLS12-381 curve.
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

// MustBLSPointFromHex unwraps a hex serialization to a G1 or G2 point on the BLS12-381 curve.
//
// Panics if conversion fails.
func MustBLSPointFromHex(hexStr string) kyber.Point {
	point, err := BLSPointFromHex(hexStr)
	if err != nil {
		panic("invalid BLS point \"" + hexStr + "\": " + err.Error())
	}

	return point
}

// BLSPubkeyHex wraps a BLS public key with simplified hex serialization.
type BLSPubkeyHex struct {
	*bls.KyberG1
}

// UnmarshalText decodes the given hex serialization of the compressed form BLS12-381 G1 point.
func (p *BLSPubkeyHex) UnmarshalText(b []byte) error {
	decodedLen := hex.DecodedLen(len(b))
	expectedLen := p.MarshalSize()
	if decodedLen != expectedLen {
		return fmt.Errorf("expected %d bytes, got %d", expectedLen, decodedLen)
	}

	data := make([]byte, expectedLen)
	if n, err := hex.Decode(data, b); err != nil {
		return err
	} else if n != expectedLen {
		return fmt.Errorf("expected %d bytes, got %d", expectedLen, n)
	}

	p.KyberG1 = bls.NullKyberG1()

	return p.UnmarshalBinary(data)
}

// MarshalText returns the hex serialization of the compressed form BLS12-381 G1 point.
func (p BLSPubkeyHex) MarshalText() ([]byte, error) {
	raw, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}

	data := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(data, raw)

	return data, nil
}
