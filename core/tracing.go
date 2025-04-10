// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"context"
	"hash/fnv"
	"sync"

	eth2api "github.com/attestantio/go-eth2-client/api"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/obolnetwork/charon/app/tracer"
)

var (
	clusterHash     []byte
	clusterHashOnce sync.Once
)

// StartDutyTrace returns a context and span rooted to the duty traceID and wrapped in a duty span.
// This creates a new trace root and should generally only be called when a new duty is scheduled
// or when a duty is received from the VC or peer.
func StartDutyTrace(ctx context.Context, duty Duty, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	dutyStr := duty.String()

	// TraceID must be globally unique, but consistent across all nodes.
	h := fnv.New128a()
	_, _ = h.Write(clusterHash)
	_, _ = h.Write([]byte(dutyStr))

	var traceID trace.TraceID
	copy(traceID[:], h.Sum(nil))

	var outerSpan, innerSpan trace.Span
	ctx, outerSpan = tracer.Start(tracer.RootedCtx(ctx, traceID), "core/duty."+duty.Type.String())
	ctx, innerSpan = tracer.Start(ctx, spanName, opts...)

	outerSpan.SetAttributes(semconv.ServiceInstanceIDKey.String(dutyStr))

	return ctx, withEndSpan{
		Span:    innerSpan,
		endFunc: func() { outerSpan.End() },
	}
}

// SetClusterHash sets the cluster hash.
func SetClusterHash(hash []byte) {
	clusterHashOnce.Do(func() {
		clusterHash = hash
	})
}

// withEndSpan wraps a trace span and calls endFunc when End is called.
type withEndSpan struct {
	trace.Span
	endFunc func()
}

func (s withEndSpan) End(options ...trace.SpanEndOption) {
	s.Span.End(options...)
	s.endFunc()
}

// WithTracing wraps component input functions with tracing spans.
func WithTracing() WireOption {
	return func(w *wireFuncs) {
		clone := *w

		w.FetcherFetch = func(parent context.Context, duty Duty, set DutyDefinitionSet) error {
			ctx, span := tracer.Start(parent, "core/fetcher.Fetch")
			defer span.End()

			return withSpanStatus(span, clone.FetcherFetch(ctx, duty, set))
		}
		w.ConsensusParticipate = func(parent context.Context, duty Duty) error {
			ctx, span := tracer.Start(parent, "core/consensus.Participate")
			defer span.End()

			return withSpanStatus(span, clone.ConsensusParticipate(ctx, duty))
		}
		w.ConsensusPropose = func(parent context.Context, duty Duty, set UnsignedDataSet) error {
			ctx, span := tracer.Start(parent, "core/consensus.Propose")
			defer span.End()

			return withSpanStatus(span, clone.ConsensusPropose(ctx, duty, set))
		}
		w.DutyDBStore = func(parent context.Context, duty Duty, set UnsignedDataSet) error {
			ctx, span := tracer.Start(parent, "core/dutydb.Store")
			defer span.End()

			return withSpanStatus(span, clone.DutyDBStore(ctx, duty, set))
		}
		w.DutyDBAwaitProposal = func(parent context.Context, slot uint64) (*eth2api.VersionedProposal, error) {
			ctx, span := tracer.Start(parent, "core/dutydb.AwaitProposal")
			defer span.End()

			vp, err := clone.DutyDBAwaitProposal(ctx, slot)

			return vp, withSpanStatus(span, err)
		}
		w.ParSigDBStoreInternal = func(parent context.Context, duty Duty, set ParSignedDataSet) error {
			ctx, span := tracer.Start(parent, "core/parsigdb.StoreInternal")
			defer span.End()

			return withSpanStatus(span, clone.ParSigDBStoreInternal(ctx, duty, set))
		}
		w.ParSigDBStoreExternal = func(parent context.Context, duty Duty, set ParSignedDataSet) error {
			ctx, span := tracer.Start(parent, "core/parsigdb.StoreExternal")
			defer span.End()

			return withSpanStatus(span, clone.ParSigDBStoreExternal(ctx, duty, set))
		}
		w.ParSigExBroadcast = func(parent context.Context, duty Duty, set ParSignedDataSet) error {
			ctx, span := tracer.Start(parent, "core/parsigex.Broadcast")
			defer span.End()

			return withSpanStatus(span, clone.ParSigExBroadcast(ctx, duty, set))
		}
		w.SigAggAggregate = func(parent context.Context, duty Duty, set map[PubKey][]ParSignedData) error {
			ctx, span := tracer.Start(parent, "core/sigagg.Aggregate")
			defer span.End()

			return withSpanStatus(span, clone.SigAggAggregate(ctx, duty, set))
		}
		w.AggSigDBStore = func(parent context.Context, duty Duty, set SignedDataSet) error {
			ctx, span := tracer.Start(parent, "core/aggsigdb.Store")
			defer span.End()

			return withSpanStatus(span, clone.AggSigDBStore(ctx, duty, set))
		}
		w.AggSigDBAwait = func(parent context.Context, duty Duty, key PubKey) (SignedData, error) {
			ctx, span := tracer.Start(parent, "core/aggsigdb.Await")
			defer span.End()

			sd, err := clone.AggSigDBAwait(ctx, duty, key)

			return sd, withSpanStatus(span, err)
		}
		w.BroadcasterBroadcast = func(parent context.Context, duty Duty, set SignedDataSet) error {
			ctx, span := tracer.Start(parent, "core/broadcaster.Broadcast")
			defer span.End()

			return withSpanStatus(span, clone.BroadcasterBroadcast(ctx, duty, set))
		}
	}
}

func withSpanStatus(span trace.Span, err error) error {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	} else {
		span.SetStatus(codes.Ok, "")
	}

	return err
}
