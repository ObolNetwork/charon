// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	"github.com/obolnetwork/charon/app/z"
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
		sig, err := tblsconv2.SigFromCore(parSig.Signature())
		if err != nil {
			return errors.Wrap(err, "signature from core")
		}
		blsSigs[parSig.ShareIdx] = sig
	}

	if len(blsSigs) < a.threshold {
		return errors.New("number of partial signatures less than threshold", z.Int("threshold", a.threshold), z.Int("got", len(blsSigs)))
	}

	// Aggregate signatures
	_, span := tracer.Start(ctx, "tbls.Aggregate")
	sig, err := tblsv2.ThresholdAggregate(blsSigs)
	span.End()
	if err != nil {
		return err
	}

	// Inject signature into one of the parSigs resulting in aggregate signed data.
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
