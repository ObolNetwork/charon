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

		w.FetcherFetch = func(parent context.Context, duty Duty, set FetchArgSet) error {
			ctx, span := tracer.Start(parent, "core/fetcher.Fetch")
			defer span.End()

			return clone.FetcherFetch(ctx, duty, set)
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
		w.SigAggAggregate = func(parent context.Context, duty Duty, key PubKey, data []ParSignedData) error {
			ctx, span := tracer.Start(parent, "core/sigagg.Aggregate")
			defer span.End()

			return clone.SigAggAggregate(ctx, duty, key, data)
		}
		w.AggSigDBStore = func(parent context.Context, duty Duty, key PubKey, data AggSignedData) error {
			ctx, span := tracer.Start(parent, "core/aggsigdb.Store")
			defer span.End()

			return clone.AggSigDBStore(ctx, duty, key, data)
		}
		w.AggSigDBAwait = func(parent context.Context, duty Duty, key PubKey) (AggSignedData, error) {
			ctx, span := tracer.Start(parent, "core/aggsigdb.Await")
			defer span.End()

			return clone.AggSigDBAwait(ctx, duty, key)
		}
		w.BroadcasterBroadcast = func(parent context.Context, duty Duty, key PubKey, data AggSignedData) error {
			ctx, span := tracer.Start(parent, "core/broadcaster.Broadcast")
			defer span.End()

			return clone.BroadcasterBroadcast(ctx, duty, key, data)
		}
	}
}
