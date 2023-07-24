// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package log

import (
	"math"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/time/rate"

	"github.com/obolnetwork/charon/app/z"
)

type FilterOption func(*filter)

// WithFilterRateLimit returns a filter option that rate limits logging by a per second limit.
func WithFilterRateLimit(limit rate.Limit) FilterOption {
	return func(f *filter) {
		f.limit = limit
	}
}

type filter struct {
	limit rate.Limit
}

// defaultFilter returns the default filter with a period of 1 minute.
func defaultFilter() filter {
	return filter{limit: rate.Every(time.Minute)}
}

// Filter returns a stateful structure logging field that results in
// logs lines being dropped if internal rate limit is exceeded.
// Usage:
//
//	filter := log.Filter()
//	for event := range eventPipe() {
//	  err := process(event)
//	  if err != nil {
//	    log.Error(ctx, "This error should only be logged max once an minute", err, filter)
//	  }
//	}
func Filter(opts ...FilterOption) z.Field {
	f := defaultFilter()
	for _, opt := range opts {
		opt(&f)
	}

	limiter := rate.NewLimiter(f.limit, 1)

	return func(add func(zap.Field)) {
		if !limiter.Allow() {
			add(zap.Field{Type: filterFieldType})
		}
	}
}

// filterFieldType is a custom zap field type that indicates the whole log should be filtered (dropped).
var filterFieldType = zapcore.FieldType(math.MaxUint8)
