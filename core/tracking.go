// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"context"

	"github.com/obolnetwork/charon/app/log"
)

// WithTracking wraps component input functions to support tracking of core components.
func WithTracking(tracker Tracker, submittedFunc func(Duty, PubKey, SignedData) error) WireOption {
	return func(w *wireFuncs) {
		clone := *w

		w.FetcherFetch = func(ctx context.Context, duty Duty, set DutyDefinitionSet) error {
			err := clone.FetcherFetch(ctx, duty, set)
			tracker.FetcherFetched(duty, set, err)

			return err
		}
		w.ConsensusPropose = func(ctx context.Context, duty Duty, set UnsignedDataSet) error {
			err := clone.ConsensusPropose(ctx, duty, set)
			tracker.ConsensusProposed(duty, set, err)

			return err
		}
		w.DutyDBStore = func(ctx context.Context, duty Duty, set UnsignedDataSet) error {
			err := clone.DutyDBStore(ctx, duty, set)
			tracker.DutyDBStored(duty, set, err)

			return err
		}
		w.ParSigDBStoreInternal = func(ctx context.Context, duty Duty, set ParSignedDataSet) error {
			err := clone.ParSigDBStoreInternal(ctx, duty, set)
			tracker.ParSigDBStoredInternal(duty, set, err)

			return err
		}
		w.ParSigExBroadcast = func(ctx context.Context, duty Duty, set ParSignedDataSet) error {
			err := clone.ParSigExBroadcast(ctx, duty, set)
			tracker.ParSigExBroadcasted(duty, set, err)

			return err
		}
		w.ParSigDBStoreExternal = func(ctx context.Context, duty Duty, set ParSignedDataSet) error {
			err := clone.ParSigDBStoreExternal(ctx, duty, set)
			tracker.ParSigDBStoredExternal(duty, set, err)

			return err
		}
		w.SigAggAggregate = func(ctx context.Context, duty Duty, key PubKey, data []ParSignedData) error {
			err := clone.SigAggAggregate(ctx, duty, key, data)
			tracker.SigAggAggregated(duty, key, data, err)

			return err
		}
		w.AggSigDBStore = func(ctx context.Context, duty Duty, key PubKey, data SignedData) error {
			err := clone.AggSigDBStore(ctx, duty, key, data)
			tracker.AggSigDBStored(duty, key, data, err)

			return err
		}
		w.BroadcasterBroadcast = func(ctx context.Context, duty Duty, pubkey PubKey, data SignedData) error {
			err := clone.BroadcasterBroadcast(ctx, duty, pubkey, data)
			tracker.BroadcasterBroadcast(duty, pubkey, data, err)
			if err != nil {
				return err
			}

			if err := submittedFunc(duty, pubkey, data); err != nil {
				log.Error(ctx, "Failed to submit duty", err)
			}

			return nil
		}
	}
}
