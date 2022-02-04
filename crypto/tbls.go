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
	"encoding/json"

	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/util/random"

	"github.com/obolnetwork/charon/app/errors"
)

// TBLSScheme wraps drand/share.PubPoly, the public commitments of a BLS secret sharing scheme
// required to recover BLS threshold signatures from signature shares.
type TBLSScheme struct {
	*share.PubPoly
}

// Pubkey returns the BLS public key.
func (t TBLSScheme) Pubkey() kyber.Point {
	return t.PubPoly.Commit()
}

// UnmarshalJSON deserializes a TBLS scheme from JSON.
func (t *TBLSScheme) UnmarshalJSON(data []byte) error {
	var encoded TBLSSchemeEncoded
	if err := json.Unmarshal(data, &encoded); err != nil {
		return errors.Wrap(err, "unmarshal TBLS scheme")
	}

	*t = *encoded.Decode()

	return nil
}

// MarshalJSON serializes a TBLS scheme to JSON.
func (t TBLSScheme) MarshalJSON() ([]byte, error) {
	encoded, err := t.Encode()
	if err != nil {
		return nil, errors.Wrap(err, "encode TBLS scheme")
	}

	return json.Marshal(encoded)
}

// TBLSSchemeEncoded is the serialized form of TBLSScheme suitable for JSON encoding.
type TBLSSchemeEncoded []BLSPubkeyHex

// Encode serializes cryptographic data.
func (t TBLSScheme) Encode() (TBLSSchemeEncoded, error) {
	base, commits := t.Info()
	if !base.Equal(BLSKeyGroup.Point().Base()) {
		return nil, errors.New("pubkey commits do not use standard base point")
	}

	enc := make([]BLSPubkeyHex, len(commits))
	for i, c := range commits {
		enc[i] = BLSPubkeyHex{c.(*bls.KyberG1)}
	}

	return enc, nil
}

// Decode reconstructs the threshold BLS commitment data.
func (t TBLSSchemeEncoded) Decode() *TBLSScheme {
	points := make([]kyber.Point, len(t))
	for i, commit := range t {
		points[i] = commit.Point
	}

	pubPoly := share.NewPubPoly(BLSKeyGroup, BLSKeyGroup.Point().Base(), points)

	return &TBLSScheme{pubPoly}
}

// NewTBLSPoly creates a new secret sharing polynomial for a BLS12-381 threshold signature scheme.
// Note that this function is not particularly secure as it constructs the root key in memory.
func NewTBLSPoly(t int) (pri *share.PriPoly, pub *share.PubPoly) {
	stream := random.New()
	secret := BLSKeyGroup.Scalar().Pick(stream)
	pri = share.NewPriPoly(BLSKeyGroup, t, secret, stream)
	pub = pri.Commit(BLSKeyGroup.Point().Base())

	return pri, pub
}
