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
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
)

func AggregateAttestations(attestations []phase0.Attestation) (phase0.Attestation, error) {
	data := attestations[0].Data
	bitfield := attestations[0].AggregationBits
	partialSignatures := make([]*bls_sig.PartialSignature, len(attestations))
	for i, att := range attestations {
		if data != att.Data {
			return phase0.Attestation{}, errors.New("attestations data mismatch")
		}

		ok, err := bitfield.Contains(att.AggregationBits)
		if err != nil || !ok {
			return phase0.Attestation{}, errors.New("attestations bitfield mismatch")
		}

		partialSig, err := BLSSigGroup.FromCompressed(att.Signature[:])
		if err != nil {
			return phase0.Attestation{}, err
		}

		partialSignatures[i] = &bls_sig.PartialSignature{
			Identifier: byte(i),
			Signature:  partialSig,
		}
	}

	blsScheme := bls_sig.NewSigPop()
	combinedSignature, err := blsScheme.CombineSignatures(partialSignatures...)
	if err != nil {
		return phase0.Attestation{}, errors.Wrap(err, "combine partial signatures")
	}

	var sig phase0.BLSSignature
	buf := BLSSigGroup.ToCompressed(&combinedSignature.Value)
	copy(sig[:], buf)

	return phase0.Attestation{
		AggregationBits: attestations[0].AggregationBits,
		Data:            attestations[0].Data,
		Signature:       sig,
	}, nil
}
