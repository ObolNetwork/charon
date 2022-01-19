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

// Package helpers defines common operations on Eth2 consensus messages.
package helpers

import (
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/share"
	"github.com/obolnetwork/charon/crypto"
	"github.com/rs/zerolog"
)

// ThresholdAggregateAttestations aggregates an array of attestations carrying TSS partial signatures.
//
// The given PubPoly contains the TSS params.
// "indices" specifies the signer indexes of the individual attestations.
//
// An aggregated attestation will be produced as long as the threshold of signatures is valid.
// Invalid signatures will be logged and skipped silently.
func ThresholdAggregateAttestations(attestations []*phase0.Attestation, indices []int, params *crypto.TBLSParams, log *zerolog.Logger) (*phase0.Attestation, error) {
	// Ensure enough signatures are present and indices are within bounds.
	// TODO(richard): DoS when validators send an invalid signature (point not curve)
	if len(attestations) == 0 {
		return nil, fmt.Errorf("called ThresholdAggregateAttestations with zero signatures")
	}
	if len(attestations) < params.Threshold() {
		return nil, NotEnoughSignaturesError{Present: len(attestations), Threshold: params.Threshold()}
	}
	if len(attestations) != len(indices) {
		return nil, fmt.Errorf("got %d attestations but %d indices", len(attestations), len(indices))
	}
	// TODO(richard): DoS when signing roots don't match, should use most common signing index instead.
	// Calculate signing roots for all attestations.
	roots := make([][32]byte, len(attestations))
	for i, attn := range attestations {
		var hashErr error
		roots[i], hashErr = attn.Data.HashTreeRoot()
		if hashErr != nil {
			return nil, fmt.Errorf("error hashing attestation %d: %w", i, hashErr)
		}
	}
	// Ensure all signing roots match.
	signingRoot := roots[0]
	for i, root := range roots[1:] {
		if signingRoot != root {
			return nil, fmt.Errorf("mismatching attestation signing roots; attn[0]=%x, attn[%d]=%x",
				signingRoot, i+1, root)
		}
	}
	// Uncompress and verify signatures.
	var shares []*share.PubShare
	for i, attn := range attestations {
		signerIndex := indices[i]
		pubkey := params.PubPoly.Eval(signerIndex)
		verifyErr := crypto.BLSSigScheme.Verify(pubkey.V, signingRoot[:], attn.Signature[:])
		if verifyErr != nil {
			// TODO(richard): Log index
			log.Warn().Err(verifyErr).Msg("Invalid partial signature")
			continue
		}
		partialSig, err := UncompressBLSSignature(&attn.Signature)
		if err != nil {
			// TODO(richard): Log index
			log.Warn().Err(err).Msg("Invalid partial signature")
			continue
		}
		pubShare := &share.PubShare{I: indices[i], V: partialSig}
		shares = append(shares, pubShare)
	}
	if len(shares) < params.Threshold() {
		return nil, NotEnoughSignaturesError{Present: len(shares), Threshold: params.Threshold()}
	}
	finalSig, commitErr := share.RecoverCommit(crypto.BLSSigGroup, shares, params.Threshold(), len(shares))
	if commitErr != nil {
		return nil, fmt.Errorf("failed to recover sigs: %w", commitErr)
	}
	compressedFinalSig := CompressBLSSignature(finalSig.(*bls.KyberG2))
	// TODO(richard): Pick correct attestation
	return &phase0.Attestation{
		AggregationBits: attestations[0].AggregationBits,
		Data:            attestations[0].Data,
		Signature:       compressedFinalSig,
	}, nil
}
