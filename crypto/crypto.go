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

// Package crypto exposes high-level cryptographic functionality.
package crypto

import (
	"github.com/drand/kyber"
	bls12381 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign/bls"
)

// BLSPairing is the BLS12-381 suite.
var BLSPairing = bls12381.NewBLS12381Suite()

// BLSKeyGroup is the G1 group.
var BLSKeyGroup = BLSPairing.G1()

// BLSSigGroup is the G2 group.
var BLSSigGroup = BLSPairing.G2()

// BLSSigScheme is the BLS12-381 signature scheme.
var BLSSigScheme = bls.NewSchemeOnG2(BLSPairing)

// DerivePubkey returns a BLS public key given a private key.
func DerivePubkey(secret kyber.Scalar) *bls12381.KyberG1 {
	return BLSKeyGroup.Point().Mul(secret, nil).(*bls12381.KyberG1)
}

// NewKeyPair creates a new random key pair.
func NewKeyPair() (secret kyber.Scalar, pubkey *bls12381.KyberG1) {
	secret = BLSPairing.G1().Scalar().Pick(BLSPairing.RandomStream())
	pubkey = DerivePubkey(secret)
	return
}
