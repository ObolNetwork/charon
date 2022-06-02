// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

// Package sigagg provides the sigagg core workflow component that
// aggregates *threshold* partial signed duty data objects
// into an aggregated signed duty data object ready to be broadcasted
// to the beacon chain.
package sigagg

import (
	"context"

	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/tracer"
	"github.com/obolnetwork/charon/app/z"
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

		s, err := tblsconv.SigFromCore(parSig.Signature)
		if err != nil {
			return errors.Wrap(err, "convert signature")
		}

		blsSigs = append(blsSigs, &bls_sig.PartialSignature{
			Identifier: byte(parSig.ShareIdx),
			Signature:  s.Value,
		})
	}

	// Aggregate signatures
	_, span := tracer.Start(ctx, "tbls.Aggregate")
	sig, err := tbls.Aggregate(blsSigs)
	span.End()
	if err != nil {
		return err
	}

	// Inject signature into resulting aggregate signed data.
	aggSig, err := getAggSignedData(duty.Type, firstParSig, sig)
	if err != nil {
		return err
	}

	log.Debug(ctx, "Aggregated threshold partial signatures", z.Any("duty", duty))

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
	case core.DutyRandao:
		return core.EncodeRandaoAggSignedData(eth2Sig), nil
	case core.DutyProposer:
		block, err := core.DecodeBlockParSignedData(data)
		if err != nil {
			return core.AggSignedData{}, err
		}
		switch block.Version {
		case spec.DataVersionPhase0:
			block.Phase0.Signature = eth2Sig
		case spec.DataVersionAltair:
			block.Altair.Signature = eth2Sig
		case spec.DataVersionBellatrix:
			block.Bellatrix.Signature = eth2Sig
		default:
			return core.AggSignedData{}, errors.New("invalid block version")
		}

		return core.EncodeBlockAggSignedData(block)
	case core.DutyExit:
		// JSON decode from previous component
		ve, err := core.DecodeSignedExitParSignedData(data)
		if err != nil {
			return core.AggSignedData{}, errors.Wrap(err, "json decoding voluntary exit")
		}

		// change signature to TSS aggregated one
		ve.Signature = eth2Sig

		// JSON encode for next component
		return core.EncodeSignedExitAggSignedData(ve)
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
	case core.DutyRandao:
		// randao is just a signature, it doesn't have other data to check
		return eth2p0.Root{}, nil
	case core.DutyProposer:
		block, err := core.DecodeBlockParSignedData(data)
		if err != nil {
			return eth2p0.Root{}, err
		}

		return block.Root()
	case core.DutyExit:
		// JSON decode from previous component
		ve, err := core.DecodeSignedExitParSignedData(data)
		if err != nil {
			return eth2p0.Root{}, errors.Wrap(err, "json decoding voluntary exit")
		}

		return ve.Message.HashTreeRoot()
	default:
		return eth2p0.Root{}, errors.New("unsupported duty type")
	}
}
