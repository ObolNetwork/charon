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
	"github.com/coinbase/kryptology/pkg/core/curves/native/bls12381"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
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
	if len(parSigs) < a.threshold {
		return errors.New("require threshold signatures")
	} else if a.threshold == 0 {
		return errors.New("invalid threshold config")
	}

	// Get all partial signatures and one partial signed data object.
	var (
		blsSigs     []*bls_sig.PartialSignature
		firstParSig core.ParSignedData
		firstRoot   eth2p0.Root
	)
	for i, parSig := range parSigs {
		root, err := getSignedRoot(duty.Type, parSig)
		if err != nil {
			return err
		}

		if i == 0 {
			firstParSig = parSig
			firstRoot = root
		} else if firstRoot != root {
			return errors.New("mismatching signed root")
		}

		s, err := new(bls12381.G2).FromCompressed((*[96]byte)(parSig.Signature))
		if err != nil {
			return errors.Wrap(err, "convert signature")
		}

		blsSigs = append(blsSigs, &bls_sig.PartialSignature{
			Identifier: byte(parSig.ShareIdx),
			Signature:  *s,
		})
	}

	// Aggregate signatures
	sig, err := tbls.Aggregate(blsSigs)
	if err != nil {
		return err
	}

	// Inject signature into resulting aggregate singed data.
	aggSig, err := getAggSignedData(duty.Type, firstParSig, sig)
	if err != nil {
		return err
	}

	// Call subscriptions.
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
	eth2Sig := tblsconv.SigToETH2(aggSig)

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
