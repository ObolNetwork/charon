// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"context"
	"fmt"
	"hash/fnv"
	"strings"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/obolnetwork/charon/app/tracer"
)

// StartDutyTrace returns a context and span rooted to the duty traceID and wrapped in a duty span.
// This creates a new trace root and should generally only be called when a new duty is scheduled
// or when a duty is received from the VC or peer.
func StartDutyTrace(ctx context.Context, duty Duty, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	h := fnv.New128a()
	_, _ = h.Write([]byte(duty.String()))

	var traceID trace.TraceID
	copy(traceID[:], h.Sum(nil))

	var outerSpan, innerSpan trace.Span
	ctx, outerSpan = tracer.Start(tracer.RootedCtx(ctx, traceID), fmt.Sprintf("core/duty.%s", strings.Title(duty.Type.String())))
	ctx, innerSpan = tracer.Start(ctx, spanName, opts...)

	outerSpan.SetAttributes(attribute.Int64("slot", duty.Slot))

	return ctx, withEndSpan{
		Span:    innerSpan,
		endFunc: func() { outerSpan.End() },
	}
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

			return clone.FetcherFetch(ctx, duty, set)
		}
		w.ConsensusParticipate = func(parent context.Context, duty Duty) error {
			ctx, span := tracer.Start(parent, "core/consensus.Participate")
			defer span.End()

			return clone.ConsensusParticipate(ctx, duty)
		}
		w.ConsensusPropose = func(parent context.Context, duty Duty, set UnsignedDataSet) error {
			ctx, span := tracer.Start(parent, "core/consensus.Propose")
			defer span.End()

			return clone.ConsensusPropose(ctx, duty, set)
		}
		w.DutyDBStore = func(parent context.Context, duty Duty, set UnsignedDataSet) error {
			ctx, span := tracer.Start(parent, "core/dutydb.Store")
			defer span.End()

			return clone.DutyDBStore(ctx, duty, set)
		}
		w.DutyDBAwaitAttestation = func(parent context.Context, slot, commIdx int64) (*eth2p0.AttestationData, error) {
			ctx, span := tracer.Start(parent, "core/dutydb.AwaitAttestation")
			defer span.End()

			return clone.DutyDBAwaitAttestation(ctx, slot, commIdx)
		}
		w.DutyDBPubKeyByAttestation = func(parent context.Context, slot, commIdx, valCommIdx int64) (PubKey, error) {
			ctx, span := tracer.Start(parent, "core/dutydb.PubKeyByAttestation")
			defer span.End()

			return clone.DutyDBPubKeyByAttestation(ctx, slot, commIdx, valCommIdx)
		}
		w.ParSigDBStoreInternal = func(parent context.Context, duty Duty, set ParSignedDataSet) error {
			ctx, span := tracer.Start(parent, "core/parsigdb.StoreInternal")
			defer span.End()

			return clone.ParSigDBStoreInternal(ctx, duty, set)
		}
		w.ParSigDBStoreExternal = func(parent context.Context, duty Duty, set ParSignedDataSet) error {
			ctx, span := tracer.Start(parent, "core/parsigdb.StoreExternal")
			defer span.End()

			return clone.ParSigDBStoreExternal(ctx, duty, set)
		}
		w.ParSigExBroadcast = func(parent context.Context, duty Duty, set ParSignedDataSet) error {
			ctx, span := tracer.Start(parent, "core/parsigex.Broadcast")
			defer span.End()

			return clone.ParSigExBroadcast(ctx, duty, set)
		}
		w.SigAggAggregate = func(parent context.Context, duty Duty, set map[PubKey][]ParSignedData) error {
			ctx, span := tracer.Start(parent, "core/sigagg.Aggregate")
			defer span.End()

			return clone.SigAggAggregate(ctx, duty, set)
		}
		w.AggSigDBStore = func(parent context.Context, duty Duty, set SignedDataSet) error {
			ctx, span := tracer.Start(parent, "core/aggsigdb.Store")
			defer span.End()

			return clone.AggSigDBStore(ctx, duty, set)
		}
		w.AggSigDBAwait = func(parent context.Context, duty Duty, key PubKey) (SignedData, error) {
			ctx, span := tracer.Start(parent, "core/aggsigdb.Await")
			defer span.End()

			return clone.AggSigDBAwait(ctx, duty, key)
		}
		w.BroadcasterBroadcast = func(parent context.Context, duty Duty, set SignedDataSet) error {
			ctx, span := tracer.Start(parent, "core/broadcaster.Broadcast")
			defer span.End()

			return clone.BroadcasterBroadcast(ctx, duty, set)
		}
	}
}
