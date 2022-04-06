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

package core

import (
	"context"

	"github.com/obolnetwork/charon/app/retry"
)

// WithAsyncRetry wraps component input functions with the async Retryer adding robustness to network issues.
func WithAsyncRetry(retryer *retry.Retryer) WireOption {
	return func(w *wireFuncs) {
		clone := *w
		w.FetcherFetch = func(ctx context.Context, duty Duty, set FetchArgSet) error {
			go retryer.DoAsync(ctx, duty.Slot, "fetcher fetch", func(ctx context.Context) error {
				return clone.FetcherFetch(ctx, duty, set)
			})

			return nil
		}
		w.ConsensusPropose = func(ctx context.Context, duty Duty, set UnsignedDataSet) error {
			go retryer.DoAsync(ctx, duty.Slot, "consensus propose", func(ctx context.Context) error {
				return clone.ConsensusPropose(ctx, duty, set)
			})

			return nil
		}
		w.ParSigExBroadcast = func(ctx context.Context, duty Duty, set ParSignedDataSet) error {
			go retryer.DoAsync(ctx, duty.Slot, "parsigex broadcast", func(ctx context.Context) error {
				return clone.ParSigExBroadcast(ctx, duty, set)
			})

			return nil
		}
		w.BroadcasterBroadcast = func(ctx context.Context, duty Duty, key PubKey, data AggSignedData) error {
			go retryer.DoAsync(ctx, duty.Slot, "bcast broadcast", func(ctx context.Context) error {
				return clone.BroadcasterBroadcast(ctx, duty, key, data)
			})

			return nil
		}
	}
}
