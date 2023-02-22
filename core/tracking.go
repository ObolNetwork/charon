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

package core

import (
	"context"
)

// WithTracking wraps component input functions to support tracking of core components.
func WithTracking(parentCtx context.Context, tracker Tracker) WireOption {
	return func(w *wireFuncs) {
		clone := *w

		w.FetcherFetch = func(ctx context.Context, duty Duty, set DutyDefinitionSet) error {
			err := clone.FetcherFetch(ctx, duty, set)
			tracker.FetcherFetched(parentCtx, duty, set, err)

			return err
		}
		w.ConsensusPropose = func(ctx context.Context, duty Duty, set UnsignedDataSet) error {
			err := clone.ConsensusPropose(ctx, duty, set)
			tracker.ConsensusProposed(parentCtx, duty, set, err)

			return err
		}
		w.DutyDBStore = func(ctx context.Context, duty Duty, set UnsignedDataSet) error {
			err := clone.DutyDBStore(ctx, duty, set)
			tracker.DutyDBStored(parentCtx, duty, set, err)

			return err
		}
		w.ParSigDBStoreInternal = func(ctx context.Context, duty Duty, set ParSignedDataSet) error {
			err := clone.ParSigDBStoreInternal(ctx, duty, set)
			tracker.ParSigDBStoredInternal(parentCtx, duty, set, err)

			return err
		}
		w.ParSigExBroadcast = func(ctx context.Context, duty Duty, set ParSignedDataSet) error {
			err := clone.ParSigExBroadcast(ctx, duty, set)
			tracker.ParSigExBroadcasted(parentCtx, duty, set, err)

			return err
		}
		w.ParSigDBStoreExternal = func(ctx context.Context, duty Duty, set ParSignedDataSet) error {
			err := clone.ParSigDBStoreExternal(ctx, duty, set)
			tracker.ParSigDBStoredExternal(parentCtx, duty, set, err)

			return err
		}
		w.SigAggAggregate = func(ctx context.Context, duty Duty, key PubKey, data []ParSignedData) error {
			err := clone.SigAggAggregate(ctx, duty, key, data)
			tracker.SigAggAggregated(parentCtx, duty, key, data, err)

			return err
		}
		w.AggSigDBStore = func(ctx context.Context, duty Duty, key PubKey, data SignedData) error {
			err := clone.AggSigDBStore(ctx, duty, key, data)
			tracker.AggSigDBStored(parentCtx, duty, key, data, err)

			return err
		}
		w.BroadcasterBroadcast = func(ctx context.Context, duty Duty, pubkey PubKey, data SignedData) error {
			err := clone.BroadcasterBroadcast(ctx, duty, pubkey, data)
			tracker.BroadcasterBroadcast(parentCtx, duty, pubkey, data, err)

			return err
		}
	}
}
