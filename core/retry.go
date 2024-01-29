// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
		// ConsensusParticipate and ConsensusPropose don't require retrying but they should be called async.
		w.ConsensusParticipate = func(ctx context.Context, duty Duty) error {
			go retryer.DoAsync(ctx, duty, "consensus", "participate", func(ctx context.Context) error {
				return clone.ConsensusParticipate(ctx, duty)
			})

			return nil
		}
		w.ConsensusPropose = func(ctx context.Context, duty Duty, set UnsignedDataSet) error {
			go retryer.DoAsync(ctx, duty, "consensus", "propose", func(ctx context.Context) error {
				return clone.ConsensusPropose(ctx, duty, set)
			})

			return nil
		}
		w.ParSigExBroadcast = func(ctx context.Context, duty Duty, set ParSignedDataSet) error {
			go retryer.DoAsync(ctx, duty, "parsigex", "broadcast", func(ctx context.Context) error {
				return clone.ParSigExBroadcast(ctx, duty, set)
			})

			return nil
		}
		w.BroadcasterBroadcast = func(ctx context.Context, duty Duty, set SignedDataSet) error {
			go retryer.DoAsync(ctx, duty, "bcast", "broadcast", func(ctx context.Context) error {
				return clone.BroadcasterBroadcast(ctx, duty, set)
			})

			return nil
		}
	}
}
