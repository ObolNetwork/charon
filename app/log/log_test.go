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

package log_test

import (
	"bytes"
	"context"
	"io"
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
	log.Warn(ctx3a, "msg3a")
	log.Warn(ctx3b, "msg3b")

	testutil.RequireGoldenBytes(t, buf.Bytes())
}

func TestErrorWrap(t *testing.T) {
	buf := setup(t)

	err1 := errors.New("first", z.Int("1", 1))
	err2 := errors.Wrap(err1, "second", z.Uint("2", 2))
	err3 := errors.Wrap(err2, "third", z.F64("3", 3))

	ctx := context.Background()
	log.Error(ctx, "err1", err1)
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
