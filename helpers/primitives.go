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

package helpers

import (
	"strconv"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	bls "github.com/drand/kyber-bls12381"
	"github.com/obolnetwork/charon/crypto"
)

// UncompressBLSSignature returns a phase0 serialized signature to a BLS G2 point.
func UncompressBLSSignature(sig *phase0.BLSSignature) (*bls.KyberG2, error) {
	point := crypto.BLSSigGroup.Point()
	err := point.UnmarshalBinary(sig[:])
	if err != nil {
		return nil, err
	}
	return point.(*bls.KyberG2), nil
}

// CompressBLSSignature serializes a BLS G2 point to a phase0 signature.
func CompressBLSSignature(point *bls.KyberG2) phase0.BLSSignature {
	buf, err := point.MarshalBinary()
	if err != nil {
		panic("failed to marshal KyberG2: " + err.Error()) // should never happen
	}
	var sig phase0.BLSSignature
	if copy(sig[:], buf) != 96 {
		panic("unexpected signature size: " + strconv.Itoa(len(buf)))
	}
	return sig
}
