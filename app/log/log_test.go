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

package log_test

import (
	"bytes"
	"context"
	"io"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -update -clean

func TestWithContext(t *testing.T) {
	buf := setup(t)

	ctx1 := context.Background()
	ctx2 := log.WithCtx(ctx1, z.Int("wrap2", 2))
	ctx3a := log.WithCtx(ctx2, z.Str("wrap3", "a"))
	ctx3b := log.WithCtx(ctx2, z.Str("wrap3", "b")) // Should override ctx3a field of same name.

	log.Debug(ctx1, "msg1", z.Int("ctx1", 1))
	log.Info(ctx2, "msg2", z.Int("ctx2", 2))
	log.Warn(ctx3a, "msg3a", nil)
	log.Warn(ctx3b, "msg3b", nil)

	testutil.RequireGoldenBytes(t, buf.Bytes())
}

func TestErrorWrap(t *testing.T) {
	buf := setup(t)

	err1 := errors.New("first", z.Int("1", 1))
	err2 := errors.Wrap(err1, "second", z.Uint("2", 2))
	err3 := errors.Wrap(err2, "third", z.F64("3", 3))

	ctx := context.Background()
	log.Warn(ctx, "err1", err1)
	log.Error(ctx, "err2", err2)
	log.Error(ctx, "err3", err3)

	testutil.RequireGoldenBytes(t, buf.Bytes())
}

func TestErrorWrapOther(t *testing.T) {
	buf := setup(t)

	err1 := io.EOF
	err2 := errors.Wrap(err1, "wrap")

	ctx := context.Background()
	log.Error(ctx, "err1", err1)
	log.Error(ctx, "err2", err2)

	testutil.RequireGoldenBytes(t, buf.Bytes())
}

func TestCopyFields(t *testing.T) {
	buf := setup(t)

	ctx1, cancel := context.WithCancel(context.Background())
	ctx1 = log.WithCtx(ctx1, z.Str("source", "source"))
	ctx2 := log.CopyFields(context.Background(), ctx1)

	cancel()
	require.Error(t, ctx1.Err())
	require.NoError(t, ctx2.Err())

	log.Info(ctx1, "see source")
	log.Info(ctx2, "also source")

	testutil.RequireGoldenBytes(t, buf.Bytes())
}

func TestFilterAll(t *testing.T) {
	buf := setup(t)

	ctx := context.Background()

	filter := log.Filter(log.WithFilterRateLimit(0)) // Limit of 0 results in no logs.
	log.Info(ctx, "should", filter)
	log.Info(ctx, "all", filter)
	log.Info(ctx, "be", filter)
	log.Info(ctx, "dropped", filter)

	testutil.RequireGoldenBytes(t, buf.Bytes())
}

func TestFilterDefault(t *testing.T) {
	buf := setup(t)

	ctx := context.Background()

	filter := log.Filter() // Default limit allows 1 per hour
	log.Info(ctx, "expect", filter)
	log.Info(ctx, "dropped", filter)
	log.Info(ctx, "dropped", filter)

	testutil.RequireGoldenBytes(t, buf.Bytes())
}

func TestFilterNone(t *testing.T) {
	buf := setup(t)

	ctx := context.Background()

	filter := log.Filter(log.WithFilterRateLimit(math.MaxInt64)) // Default limit allows 1 per hour
	log.Info(ctx, "expect1", filter)
	time.Sleep(time.Millisecond) // Sleep a little since we do not configure bursts.
	log.Info(ctx, "expect2", filter)
	time.Sleep(time.Millisecond)
	log.Info(ctx, "expect3", filter)
	time.Sleep(time.Millisecond)

	testutil.RequireGoldenBytes(t, buf.Bytes())
}

// setup returns a buffer that logs are written to and stubs non-deterministic logging fields.
func setup(t *testing.T) *bytes.Buffer {
	t.Helper()

	var buf zaptest.Buffer

	log.InitLoggerForT(t, &buf, func(config *zapcore.EncoderConfig) {
		config.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
			enc.AppendString("00:00")
		}
	})

	return &buf.Buffer
}
