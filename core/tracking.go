// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"context"

	"github.com/obolnetwork/charon/app/log"
)

// WithTracking wraps component input functions to support tracking of core components.
func WithTracking(tracker Tracker, inclusion InclusionChecker) WireOption {
	return func(w *wireFuncs) {
		clone := *w

		w.FetcherFetch = func(ctx context.Context, duty Duty, set DutyDefinitionSet) error {
			err := clone.FetcherFetch(ctx, duty, set)
			tracker.FetcherFetched(duty, set, err)

			return err
		}
		// TODO(corver): Should we track the new ConsensusParticipate function?
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
		w.SigAggAggregate = func(ctx context.Context, duty Duty, set map[PubKey][]ParSignedData) error {
			err := clone.SigAggAggregate(ctx, duty, set)
			tracker.SigAggAggregated(duty, set, err)

			return err
		}
		w.AggSigDBStore = func(ctx context.Context, duty Duty, set SignedDataSet) error {
			err := clone.AggSigDBStore(ctx, duty, set)
			tracker.AggSigDBStored(duty, set, err)

			return err
		}
		w.BroadcasterBroadcast = func(ctx context.Context, duty Duty, set SignedDataSet) error {
			// Check inclusion even if we fail to broadcast, since peers may succeed.
			if err := inclusion.Submitted(duty, set); err != nil {
				log.Error(ctx, "Bug: failed to submit duty to inclusion checker", err)
			}

			err := clone.BroadcasterBroadcast(ctx, duty, set)
			tracker.BroadcasterBroadcast(duty, set, err)
			if err != nil {
				return err
			}

			return nil
		}
	}
}
