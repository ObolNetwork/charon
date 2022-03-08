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

// Package sigagg provides the sigagg core workflow component that
// aggregates *threshold* partial signed duty data objects
// into an aggregated signed duty data object ready to be broadcasted
// to the beacon chain.
package sigagg

import (
	"context"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	bls12381 "github.com/dB2510/kryptology/pkg/core/curves/native/bls12-381"
	"github.com/dB2510/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/tbls"
)

// New returns a new aggregator instance.
func New(threshold int) *Aggregator {
	return &Aggregator{threshold: threshold}
}

// Aggregator aggregates *threshold* partial signed duty data objects
// into an aggregated signed duty data object ready to be broadcasted.
type Aggregator struct {
	threshold int
	subs      []func(context.Context, core.Duty, core.PubKey, core.AggSignedData) error
}

// Subscribe registers a callback for aggregated signed duty data.
func (a *Aggregator) Subscribe(fn func(context.Context, core.Duty, core.PubKey, core.AggSignedData) error) {
	a.subs = append(a.subs, fn)
}

// Aggregate aggregates the partially signed duty data for the DV.
func (a *Aggregator) Aggregate(ctx context.Context, duty core.Duty, pubkey core.PubKey, parSigs []core.ParSignedData) error {
	if len(parSigs) < a.threshold || len(parSigs) == 0 {
		return errors.New("require threshold signatures")
	}

	var (
		blsSigs []*bls_sig.PartialSignature
		first   core.ParSignedData
		root    eth2p0.Root
	)
	for i, parSig := range parSigs {
		r, err := getSignedRoot(duty.Type, parSig)
		if err != nil {
			return err
		}

		if i == 0 {
			first = parSig
			root = r
		} else if root != r {
			return errors.New("mismatching signed root")
		}

		s, err := bls12381.NewG2().FromCompressed(parSig.Signature)
		if err != nil {
			return errors.Wrap(err, "convert signature")
		}

		blsSigs = append(blsSigs, &bls_sig.PartialSignature{
			Identifier: byte(parSig.Index),
			Signature:  s,
		})
	}

	sig, err := tbls.Aggregate(blsSigs)
	if err != nil {
		return err
	}

	aggSig, err := getAggSignedData(duty.Type, first, sig)
	if err != nil {
		return err
	}

	for _, sub := range a.subs {
		err := sub(ctx, duty, pubkey, aggSig)
		if err != nil {
			return err
		}
	}

	return nil
}

// getAggSignedData returns the encoded aggregated signed data by injecting the aggregated signature.
func getAggSignedData(typ core.DutyType, data core.ParSignedData, aggSig *bls_sig.Signature) (core.AggSignedData, error) {
	sigBytes, err := aggSig.MarshalBinary()
	if err != nil {
		return core.AggSignedData{}, errors.Wrap(err, "marshal signature")
	}

	var eth2Sig eth2p0.BLSSignature
	copy(eth2Sig[:], sigBytes)

	switch typ {
	case core.DutyAttester:
		att, err := core.DecodeAttestationParSignedData(data)
		if err != nil {
			return core.AggSignedData{}, err
		}
		att.Signature = eth2Sig

		return core.EncodeAttestationAggSignedData(att)
	default:
		return core.AggSignedData{}, errors.New("unsupported duty type")
	}
}

// getSignedRoot returns the signed object root from the partial signed data.
func getSignedRoot(typ core.DutyType, data core.ParSignedData) (eth2p0.Root, error) {
	switch typ {
	case core.DutyAttester:
		att, err := core.DecodeAttestationParSignedData(data)
		if err != nil {
			return eth2p0.Root{}, err
		}

		b, err := att.Data.HashTreeRoot()
		if err != nil {
			return eth2p0.Root{}, errors.Wrap(err, "hash attestion data")
		}

		return b, nil
	default:
		return eth2p0.Root{}, errors.New("unsupported duty type")
	}
}
