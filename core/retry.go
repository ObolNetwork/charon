// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
			go retryer.DoAsync(ctx, duty, "fetcher", "fetch", func(ctx context.Context) error {
				return clone.FetcherFetch(ctx, duty, set)
			})

			return nil
		}
		w.ParSigExBroadcast = func(ctx context.Context, duty Duty, set ParSignedDataSet) error {
			go retryer.DoAsync(ctx, duty, "parsigex", "broadcast", func(ctx context.Context) error {
				return clone.ParSigExBroadcast(ctx, duty, set)
			})

			return nil
		}
		w.BroadcasterBroadcast = func(ctx context.Context, duty Duty, key PubKey, data SignedData) error {
			go retryer.DoAsync(ctx, duty, "bcast", "broadcast", func(ctx context.Context) error {
				return clone.BroadcasterBroadcast(ctx, duty, key, data)
			})

			return nil
		}
	}
}
