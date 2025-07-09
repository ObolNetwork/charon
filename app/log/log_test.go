// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package log_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
	"golang.org/x/time/rate"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -update -clean

func TestWithTopic(t *testing.T) {
	testLoggers(t, func(*testing.T) {
		ctx := log.WithTopic(context.Background(), "topic")
		log.Debug(ctx, "msg1", z.Int("ctx1", 1))
		log.Info(ctx, "msg2", z.Int("ctx2", 2))
	})
}

func TestWithContext(t *testing.T) {
	testLoggers(t, func(*testing.T) {
		ctx1 := context.Background()
		ctx2 := log.WithCtx(ctx1, z.Int("wrap2", 2))
		ctx3a := log.WithCtx(ctx2, z.Str("wrap3", "a"))
		ctx3b := log.WithCtx(ctx2, z.Str("wrap3", "b")) // Should override ctx3a field of same name.

		log.Debug(ctx1, "msg1", z.Int("ctx1", 1))
		log.Info(ctx2, "msg2", z.Int("ctx2", 2))
		log.Warn(ctx3a, "msg3a", nil)
		log.Warn(ctx3b, "msg3b", nil)
	})
}

func TestErrorWrap(t *testing.T) {
	testLoggers(t, func(*testing.T) {
		err1 := errors.New("first", z.Int("1", 1))
		err2 := errors.Wrap(err1, "second", z.Uint("2", 2))
		err3 := errors.Wrap(err2, "third", z.F64("3", 3))

		ctx := context.Background()
		log.Warn(ctx, "err1", err1)
		log.Error(ctx, "err2", err2)
		log.Error(ctx, "err3", err3)
	})
}

func TestErrorWrapOther(t *testing.T) {
	testLoggers(t, func(*testing.T) {
		err1 := io.EOF
		err2 := errors.Wrap(err1, "wrap")

		ctx := context.Background()
		log.Error(ctx, "err1", err1)
		log.Error(ctx, "err2", err2)
	})
}

func TestCopyFields(t *testing.T) {
	testLoggers(t, func(t *testing.T) {
		t.Helper()

		ctx1, cancel := context.WithCancel(context.Background())
		ctx1 = log.WithCtx(ctx1, z.Str("source", "source"))
		ctx2 := log.CopyFields(context.Background(), ctx1)

		cancel()
		require.Error(t, ctx1.Err())
		require.NoError(t, ctx2.Err())

		log.Info(ctx1, "see source")
		log.Info(ctx2, "also source")
	})
}

func TestFilterDefault(t *testing.T) {
	testLoggers(t, func(*testing.T) {
		ctx := context.Background()

		filter := log.Filter() // Default limit allows 1 per hour
		log.Info(ctx, "expect", filter)
		log.Info(ctx, "dropped", filter)
		log.Info(ctx, "dropped", filter)
	})
}

func TestFilterNone(t *testing.T) {
	testLoggers(t, func(*testing.T) {
		ctx := context.Background()

		filter := log.Filter(log.WithFilterRateLimit(rate.Inf)) // Infinite rate limit allows all.
		log.Info(ctx, "expect1", filter)
		log.Info(ctx, "expect2", filter)
		log.Info(ctx, "expect3", filter)
		log.Info(ctx, "expect4", filter)
	})
}

var ErrTest = errors.NewSentinel("test")

func TestSentinelStack(t *testing.T) {
	testLoggers(t, func(*testing.T) {
		ctx := context.Background()

		log.Error(ctx, "test", errors.Wrap(ErrTest, "wrap sentinel"))
	})
}

func testLoggers(t *testing.T, testFunc func(t *testing.T)) {
	t.Helper()

	loggers := map[string]func(_ *testing.T, ws zapcore.WriteSyncer, opts ...func(*zapcore.EncoderConfig)){
		"console": log.InitConsoleForT,
		"logfmt":  log.InitLogfmtForT,
		"json":    log.InitJSONForT,
	}

	for name, initFunc := range loggers {
		t.Run(name, func(t *testing.T) {
			var buf zaptest.Buffer
			initFunc(t, &buf, func(config *zapcore.EncoderConfig) {
				config.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
					enc.AppendString("00:00")
				}
			})
			testFunc(t)
			testutil.RequireGoldenBytes(t, buf.Bytes())
		})
	}
}

func TestInstance(t *testing.T) {
	buf := zaptest.Buffer{}
	clock := clockwork.NewFakeClockAt(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	logger := log.NewConsoleForT(t, &buf, log.WithClock(clock))
	ctx := log.WithLogger(context.Background(), logger)

	clock.Advance(time.Minute)
	log.Info(ctx, "info1", z.Int("1", 1))
	clock.Advance(time.Minute)
	log.Warn(ctx, "warn2", io.EOF, z.Int("2", 2))

	testutil.RequireGoldenBytes(t, buf.Bytes())
}
