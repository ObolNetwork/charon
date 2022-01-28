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

package log

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
)

var logger zerolog.Logger

//nolint: gochecknoinits
func init() {
	InitConsoleLogger()
}

// InitJSONLogger initialises a JSON logger for production usage.
func InitJSONLogger() {
	logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
	zerolog.DefaultContextLogger = &logger
}

// InitConsoleLogger initialises a human-friendly colorised logger.
func InitConsoleLogger(options ...func(w *zerolog.ConsoleWriter)) {
	logger = zerolog.New(zerolog.NewConsoleWriter(options...)).With().Timestamp().Logger()
	zerolog.DefaultContextLogger = &logger
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	zerolog.CallerMarshalFunc = func(file string, line int) string {
		const trimBefore = "charon/"
		if i := strings.Index(file, trimBefore); i > 0 {
			file = file[i+len(trimBefore):]
		}

		return file + ":" + strconv.Itoa(line)
	}
}

// WithContext returns a fluent-API to build a child context containing contextual logging fields.
//
//   ctx = log.WithContext(ctx).Str("foo", "bar").Ctx() // All subsequent logs using this context will contain "foo=bar".
//   ...
//   log.Info(ctx).Msg("something happened") // Contains "foo=bar".
//nolint:revive
func WithContext(ctx context.Context) *builder {
	return &builder{
		zctx: zerolog.Ctx(ctx).With(),
		ctx:  ctx,
	}
}

// WithComponent is a convenience function that returns a child context with the component contextual logging field set.
func WithComponent(ctx context.Context, component string) context.Context {
	return WithContext(ctx).Str("component", component).Ctx()
}

func Debug(ctx context.Context) *zerolog.Event {
	return zerolog.Ctx(ctx).Debug().Caller(1)
}

func Info(ctx context.Context) *zerolog.Event {
	return zerolog.Ctx(ctx).Info().Stack().Caller(1)
}

func Warn(ctx context.Context) *zerolog.Event {
	return zerolog.Ctx(ctx).Warn().Stack().Caller(1)
}

func Error(ctx context.Context, err error) *zerolog.Event {
	return zerolog.Ctx(ctx).Error().Stack().Err(err).Caller(1)
}

// builder is a fluent-style API for a new sub-logger with contextual fields to be associated with final child-context via Ctx.
type builder struct {
	zctx zerolog.Context
	ctx  context.Context
}

// Ctx returns the final child-context containing the sub-logger.
func (b *builder) Ctx() context.Context {
	newLogger := b.zctx.Logger()
	return (&newLogger).WithContext(b.ctx)
}

// Str adds the field key with val as a string to the sub-logger context.
func (b *builder) Str(key, val string) *builder {
	b.zctx = b.zctx.Str(key, val)
	return b
}

// Stringer adds the field key with val.String() (or null if val is nil) to the sub-logger context.
func (b *builder) Stringer(key string, val fmt.Stringer) *builder {
	b.zctx = b.zctx.Stringer(key, val)
	return b
}

// Bytes adds the field key with val as a []byte to the sub-logger context.
func (b *builder) Bytes(key string, val []byte) *builder {
	b.zctx = b.zctx.Bytes(key, val)
	return b
}

// Hex adds the field key with val as a hex string to the sub-logger context.
func (b *builder) Hex(key string, val []byte) *builder {
	b.zctx = b.zctx.Bytes(key, val)
	return b
}

// Int adds the field key with i as an int to the sub-logger context.
func (b *builder) Int(key string, i int) *builder {
	b.zctx = b.zctx.Int(key, i)
	return b
}

// Int64 adds the field key with i as a int64 to the sub-logger context.
func (b *builder) Int64(key string, i int64) *builder {
	b.zctx = b.zctx.Int64(key, i)
	return b
}

// Uint64 adds the field key with i as an uint64 to the sub-logger context.
func (b *builder) Uint64(key string, i uint64) *builder {
	b.zctx = b.zctx.Uint64(key, i)
	return b
}
