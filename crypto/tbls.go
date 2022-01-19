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
	"fmt"

	"github.com/drand/kyber"
	"github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/util/random"
)

// TBLSParams wraps drand/share.PubPoly, the public commitments of a BLS secret sharing scheme
// required to recover BLS threshold signatures from signature shares.
type TBLSParams struct {
	*share.PubPoly
	N int
}

// Pubkey returns the BLS public key.
func (t *TBLSParams) Pubkey() kyber.Point {
	return t.PubPoly.Commit()
}

// UnmarshalJSON deserializes a TBLS scheme from JSON.
func (t *TBLSParams) UnmarshalJSON(data []byte) error {
	var encoded tblsParamsEncoded
	if err := json.Unmarshal(data, &encoded); err != nil {
		return fmt.Errorf("failed to unmarshal TBLS scheme: %w", err)
	}
	decoded, err := encoded.decode()
	if err != nil {
		return fmt.Errorf("failed to decode TBLS scheme: %w", err)
	}
	*t = *decoded
	return nil
}

// MarshalJSON serializes a TBLS scheme to JSON.
func (t *TBLSParams) MarshalJSON() ([]byte, error) {
	encoded, err := t.encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode TBLS scheme: %w", err)
	}
	return json.Marshal(encoded)
}

// tblsParamsEncoded is the serialized form of TBLSParams suitable for JSON encoding.
type tblsParamsEncoded struct {
	Commits []BLSPubkeyHex `json:"commits"`
	N       int            `json:"n"`
}

// encode serializes cryptographic data.
func (t *TBLSParams) encode() (*tblsParamsEncoded, error) {
	base, commits := t.Info()
	if !base.Equal(BLSKeyGroup.Point().Base()) {
		return nil, fmt.Errorf("pubkey commits do not use standard base point")
	}
	enc := new(tblsParamsEncoded)
	enc.N = t.N
	enc.Commits = make([]BLSPubkeyHex, len(commits))
	for i, c := range commits {
		enc.Commits[i] = BLSPubkeyHex{c.(*bls.KyberG1)}
	}
	return enc, nil
}

// decode reconstructs the threshold BLS commitment data.
func (t *tblsParamsEncoded) decode() (*TBLSParams, error) {
	points := make([]kyber.Point, len(t.Commits))
	for i, commit := range t.Commits {
		points[i] = commit.KyberG1
	}
	pubPoly := share.NewPubPoly(BLSKeyGroup, BLSKeyGroup.Point().Base(), points)
	return &TBLSParams{
		PubPoly: pubPoly,
		N:       t.N,
	}, nil
}

// NewTBLSPoly creates a new secret sharing polynomial for a BLS12-381 threshold signature scheme.
// Note that this function is not particularly secure as it constructs the root key in memory.
func NewTBLSPoly(t uint) (pri *share.PriPoly, pub *share.PubPoly) {
	stream := random.New()
	secret := BLSKeyGroup.Scalar().Pick(stream)
	pri = share.NewPriPoly(BLSKeyGroup, int(t), secret, stream)
	pub = pri.Commit(BLSKeyGroup.Point().Base())
	return
}
