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

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/tracer"
	"github.com/obolnetwork/charon/core"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
	tblsconv2 "github.com/obolnetwork/charon/tbls/v2/tblsconv"
)

// New returns a new aggregator instance.
func New(threshold int) *Aggregator {
	return &Aggregator{threshold: threshold}
}

// Aggregator aggregates *threshold* partial signed duty data objects
// into an aggregated signed duty data object ready to be broadcasted.
type Aggregator struct {
	threshold int
	subs      []func(context.Context, core.Duty, core.PubKey, core.SignedData) error
}

// Subscribe registers a callback for aggregated signed duty data.
func (a *Aggregator) Subscribe(fn func(context.Context, core.Duty, core.PubKey, core.SignedData) error) {
	a.subs = append(a.subs, fn)
}

// Aggregate aggregates the partially signed duty data for the DV.
func (a *Aggregator) Aggregate(ctx context.Context, duty core.Duty, pubkey core.PubKey, parSigs []core.ParSignedData) error {
	ctx = log.WithTopic(ctx, "sigagg")

	if len(parSigs) < a.threshold {
		return errors.New("require threshold signatures")
	} else if a.threshold == 0 {
		return errors.New("invalid threshold config")
	}

	// Get all partial signatures.
	blsSigs := make(map[int]tblsv2.Signature)
	for _, parSig := range parSigs {
		blsSigs[parSig.ShareIdx] = tblsconv2.SigFromCore(parSig.Signature())
	}

	// Aggregate signatures
	_, span := tracer.Start(ctx, "tbls.Aggregate")
	sig, err := tblsv2.ThresholdAggregate(blsSigs)
	span.End()
	if err != nil {
		return err
	}

	// Inject signature into one of te parSigs resulting in aggregate signed data.
	aggSig, err := parSigs[0].SetSignature(tblsconv2.SigToCore(sig))
	if err != nil {
		return err
	}

	log.Debug(ctx, "Threshold aggregated partial signatures")

	// Call subscriptions.
	for _, sub := range a.subs {
		clone, err := aggSig.Clone() // Clone before calling each subscriber.
		if err != nil {
			return err
		}

		if err := sub(ctx, duty, pubkey, clone); err != nil {
			return err
		}
	}

	return nil
}
