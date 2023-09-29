// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package sigagg provides the sigagg core workflow component that
// aggregates *threshold* partial signed duty data objects
// into an aggregated signed duty data object ready to be broadcasted
// to the beacon chain.
package sigagg

import (
	"context"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/tracer"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// New returns a new aggregator instance.
func New(threshold int, verifyFunc func(context.Context, core.PubKey, core.SignedData) error) (*Aggregator, error) {
	if threshold <= 0 {
		return nil, errors.New("invalid threshold", z.Int("threshold", threshold))
	}

	return &Aggregator{
		threshold:  threshold,
		verifyFunc: verifyFunc,
	}, nil
}

// Aggregator aggregates *threshold* partial signed duty data objects
// into an aggregated signed duty data object ready to be broadcasted.
type Aggregator struct {
	threshold  int
	verifyFunc func(context.Context, core.PubKey, core.SignedData) error
	subs       []func(context.Context, core.Duty, core.SignedDataSet) error
}

// Subscribe registers a callback for aggregated signed duty data.
func (a *Aggregator) Subscribe(fn func(context.Context, core.Duty, core.SignedDataSet) error) {
	a.subs = append(a.subs, fn)
}

// Aggregate aggregates the partially signed duty datas for the set of DVs.
func (a *Aggregator) Aggregate(ctx context.Context, duty core.Duty, set map[core.PubKey][]core.ParSignedData) error {
	ctx = log.WithTopic(ctx, "sigagg")

	if len(set) == 0 {
		return errors.New("empty partial signed data set")
	}

	output := make(core.SignedDataSet)
	for pubkey, parSigs := range set {
		signed, err := a.aggregate(ctx, pubkey, parSigs)
		if err != nil {
			return errors.Wrap(err, "threshold aggregate", z.Any("pubkey", pubkey))
		}

		output[pubkey] = signed
	}

	log.Debug(ctx, "Threshold aggregated partial signatures")

	// Call subscriptions.
	for _, sub := range a.subs {
		// Clone before calling each subscriber.
		cloned, err := output.Clone()
		if err != nil {
			return err
		}

		if err := sub(ctx, duty, cloned); err != nil {
			return err
		}
	}

	return nil
}

// aggregate threshold aggregates the partial signed data for a provided DV.
func (a *Aggregator) aggregate(ctx context.Context, pubkey core.PubKey, parSigs []core.ParSignedData) (core.SignedData, error) {
	if len(parSigs) < a.threshold {
		return nil, errors.New("require threshold signatures")
	}

	// +=============+============+============+============+============+
	// | Data/Charon |   Data0    |   Data1    |   Data2    |   Data3    |
	// +=============+============+============+============+============+
	// | Charon 0    | ParSig[00] | ParSig[01] | ParSig[02] | ParSig[03] |
	// 	+-------------+------------+------------+------------+------------+
	// | Charon 1    | ParSig[10] | ParSig[01] | ParSig[12] | ParSig[13] |
	// 	+-------------+------------+------------+------------+------------+
	// | Charon 2    | ParSig[20] | ParSig[21] | ParSig[22] | ParSig[23] |
	// 	+-------------+------------+------------+------------+------------+
	// | Charon 3    | ParSig[30] | ParSig[31] | ParSig[32] | ParSig[33] |
	// 	+-------------+------------+------------+------------+------------+
	// | Aggregate   | Sig[0]     | Sig[1]     | Sig[2]     | Sig[3]     |
	// 	+-------------+------------+------------+------------+------------+

	rows := make(map[int][]tbls.Signature)
	for _, parSig := range parSigs {
		var sigs []tbls.Signature
		for _, s := range parSig.Signatures() {
			sig, err := tblsconv.SigFromCore(s.Signature())
			if err != nil {
				return nil, errors.Wrap(err, "signature from core")
			}

			sigs = append(sigs, sig)
		}

		rows[parSig.ShareIdx] = sigs
	}

	if len(rows) < a.threshold {
		return nil, errors.New("number of partial signatures less than threshold", z.Int("threshold", a.threshold), z.Int("got", len(rows)))
	}

	// Check if each peer has the same number of signatures.
	sigLens := make(map[int]struct{})
	sigLen := 0
	for _, row := range rows {
		sigLen = len(row)
		sigLens[sigLen] = struct{}{}
	}
	if len(sigLens) > 1 {
		return nil, errors.New("number of signatures for each peer doesn't match")
	}

	// Aggregate signatures
	_, span := tracer.Start(ctx, "tbls.Aggregate")
	var aggregatedRow []core.Signature
	for i := 0; i < sigLen; i++ {
		column := make(map[int]tbls.Signature)
		for shareIdx, parsig := range rows {
			column[shareIdx] = parsig[i]
		}

		sig, err := tbls.ThresholdAggregate(column)
		if err != nil {
			return nil, err
		}

		aggregatedRow = append(aggregatedRow, tblsconv.SigToCore(sig))
	}
	span.End()

	// Inject signature into one of the parSigs resulting in aggregate signed data.
	aggSigs, err := parSigs[0].SetSignatures(aggregatedRow)
	if err != nil {
		return nil, err
	}

	if err := a.verifyFunc(ctx, pubkey, aggSigs); err != nil {
		return nil, err
	}

	return aggSigs, nil
}

// NewVerifier returns a signature verification function for aggregated signatures.
func NewVerifier(eth2Cl eth2wrap.Client) func(context.Context, core.PubKey, core.SignedData) error {
	return func(ctx context.Context, pubkey core.PubKey, data core.SignedData) error {
		tblsPubkey, err := tblsconv.PubkeyFromCore(pubkey)
		if err != nil {
			return errors.Wrap(err, "pubkey from core")
		}

		eth2Signed, ok := data.(core.Eth2SignedData)
		if !ok {
			return errors.New("invalid eth2 signed data")
		}

		err = core.VerifyEth2SignedData(ctx, eth2Cl, eth2Signed, tblsPubkey)
		if err != nil {
			return errors.Wrap(err, "aggregate signature verification failed")
		}

		return nil
	}
}
