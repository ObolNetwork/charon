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

package krypto

import (
	bls12381 "github.com/coinbase/kryptology/pkg/core/curves/native/bls12-381"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
)

// Pairing is the BLS12-381 Engine initialising G1 and G2 groups.
var Pairing = bls12381.NewEngine()

// KeyGroup is the G1 group.
var KeyGroup = Pairing.G1

// BlsScheme is the BLS12-381 signature scheme.
var BlsScheme = bls_sig.NewSigPop()
