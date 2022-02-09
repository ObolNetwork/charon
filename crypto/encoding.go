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

	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
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
		return nil, errors.Wrap(err, "decode hex")
	}

	var p kyber.Point

	switch len(b) {
	case 48:
		p = bls.NullKyberG1()
	case 96:
		p = bls.NullKyberG2()
	default:
		return nil, errors.New("invalid length", z.Int("len", len(b)))
	}

	if p.MarshalSize() != len(b) {
		return nil, errors.New("unexpected marshal length")
	}

	if err := p.UnmarshalBinary(b); err != nil {
		return nil, errors.Wrap(err, "unmarshal point")
	}

	return p, nil
}

// BLSPubkeyHex wraps a BLS public key with simplified hex serialization.
type BLSPubkeyHex struct {
	kyber.Point
}

// UnmarshalText decodes the given hex serialization of the compressed form BLS12-381 G1 point.
func (p *BLSPubkeyHex) UnmarshalText(b []byte) error {
	decodedLen := hex.DecodedLen(len(b))
	if decodedLen != new(bls.KyberG1).MarshalSize() {
		return errors.New("expected marshal length")
	}

	data := make([]byte, decodedLen)
	if n, err := hex.Decode(data, b); err != nil {
		return errors.Wrap(err, "decode bls hex")
	} else if n != decodedLen {
		return errors.New("expected decode length")
	}

	p.Point = bls.NullKyberG1()

	if err := p.UnmarshalBinary(data); err != nil {
		return errors.Wrap(err, "unmarshal")
	}

	return nil
}

// MarshalText returns the hex serialization of the compressed form BLS12-381 G1 point.
func (p BLSPubkeyHex) MarshalText() ([]byte, error) {
	raw, err := p.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "marshal binary")
	}

	data := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(data, raw)

	return data, nil
}
