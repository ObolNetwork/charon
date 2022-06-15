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

	"github.com/obolnetwork/charon/app/retry"
)

// WithAsyncRetry wraps component input functions with the async Retryer adding robustness to network issues.
func WithAsyncRetry(retryer *retry.Retryer[Duty]) WireOption {
	return func(w *wireFuncs) {
		clone := *w
		w.FetcherFetch = func(ctx context.Context, duty Duty, set DutyDefinitionSet) error {
			go retryer.DoAsync(ctx, duty, "fetcher fetch", func(ctx context.Context) error {
				return clone.FetcherFetch(ctx, duty, set)
			})

			return nil
		}
		w.ConsensusPropose = func(ctx context.Context, duty Duty, set UnsignedDataSet) error {
			go retryer.DoAsync(ctx, duty, "consensus propose", func(ctx context.Context) error {
				return clone.ConsensusPropose(ctx, duty, set)
			})

			return nil
		}
		w.ParSigExBroadcast = func(ctx context.Context, duty Duty, set ParSignedDataSet) error {
			go retryer.DoAsync(ctx, duty, "parsigex broadcast", func(ctx context.Context) error {
				return clone.ParSigExBroadcast(ctx, duty, set)
			})

			return nil
		}
		w.BroadcasterBroadcast = func(ctx context.Context, duty Duty, key PubKey, data SignedData) error {
			go retryer.DoAsync(ctx, duty, "bcast broadcast", func(ctx context.Context) error {
				return clone.BroadcasterBroadcast(ctx, duty, key, data)
			})

			return nil
		}
	}
}
