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

package log

import (
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

// WithFilterPeriod returns a filter option that rate limits logging by allowing one log per period.
func WithFilterPeriod(period time.Duration) FilterOption {
	return func(f *filter) {
		f.limit = rate.Limit(float64(time.Second) / float64(period))
	}
}

type filter struct {
	limit rate.Limit
}

// defaultFilter returns the default filter with a period of 1 hour.
func defaultFilter() filter {
	var f filter
	WithFilterPeriod(time.Hour)(&f)

	return f
}

// Filter returns a stateful structure logging field that results in
// logs lines being dropped if internal rate limit is exceeded.
// Usage:
//
//	filter := log.Filter()
//	for event := range eventPipe() {
//	  err := process(event)
//	  if err != nil {
//	    log.Error(ctx, "This error should only be logged max once an hour", err, filter)
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
var filterFieldType = zapcore.FieldType(255)
